package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
)

// gitignoreIndex накапливает паттерны .gitignore по мере обхода проекта и
// отвечает, игнорирует ли git данный путь. Семантика паттернов (якоря,
// каталоги, отрицания, порядок) — из go-git; здесь только сбор файлов.
//
// Паттерны применяются относительно корня git-репозитория, а не projectRoot:
// glint часто запускают на подкаталоге (glint check backend frontend), а
// паттерн вида /frontend/report/ лежит в корневом .gitignore. Поэтому при
// создании индекс поднимается до каталога с .git и загружает .gitignore всех
// предков projectRoot; .gitignore посещаемых каталогов добавляет walker через
// addDir. Паттерн несёт домен своего каталога, так что накопление паттернов
// из уже пройденных веток не влияет на соседние.
type gitignoreIndex struct {
	root     string // абсолютный корень применения паттернов
	patterns []gitignore.Pattern
}

// newGitignoreIndex строит индекс для projectRoot: находит корень репозитория
// и загружает .gitignore каждого предка projectRoot (сам projectRoot загрузит
// walker при входе в каталог).
func newGitignoreIndex(projectRoot string) (*gitignoreIndex, error) {
	absProject, err := filepath.Abs(projectRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve project root %q: %w", projectRoot, err)
	}
	idx := &gitignoreIndex{root: findGitRepoRoot(absProject)}

	chain, err := ancestorChain(idx.root, filepath.Dir(absProject))
	if err != nil {
		return nil, err
	}
	for _, dir := range chain {
		if err := idx.addDir(dir); err != nil {
			return nil, err
		}
	}
	return idx, nil
}

// findGitRepoRoot поднимается от start до каталога, содержащего .git
// (каталог или файл — worktree). Если репозитория нет, корнем остаётся start:
// одиночный .gitignore без git тоже выражает волю проекта.
func findGitRepoRoot(start string) string {
	dir := start
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return start
		}
		dir = parent
	}
}

// ancestorChain возвращает каталоги от root (включительно) до last
// (включительно) сверху вниз; пустой срез, если last выше root.
func ancestorChain(root, last string) ([]string, error) {
	rel, err := filepath.Rel(root, last)
	if err != nil {
		return nil, fmt.Errorf("relate %q to %q: %w", last, root, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return []string{}, nil
	}
	chain := []string{root}
	if rel == "." {
		return chain, nil
	}
	dir := root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		dir = filepath.Join(dir, part)
		chain = append(chain, dir)
	}
	return chain, nil
}

// addDir загружает .gitignore каталога, если он там есть. Каталог задаёт
// домен паттернов: они действуют только внутри него.
func (g *gitignoreIndex) addDir(dir string) error {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolve dir %q: %w", dir, err)
	}
	content, err := os.ReadFile(filepath.Join(absDir, ".gitignore"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read %s: %w", filepath.Join(absDir, ".gitignore"), err)
	}

	domain, err := g.split(absDir)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		g.patterns = append(g.patterns, gitignore.ParsePattern(line, domain))
	}
	return nil
}

// ignored сообщает, исключает ли git этот путь. Сам корень не проверяется:
// запуск glint на игнорируемом каталоге — явное решение пользователя.
func (g *gitignoreIndex) ignored(path string, isDir bool) (bool, error) {
	if len(g.patterns) == 0 {
		return false, nil
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false, fmt.Errorf("resolve %q: %w", path, err)
	}
	parts, err := g.split(absPath)
	if err != nil {
		return false, err
	}
	if len(parts) == 0 {
		return false, nil
	}
	return gitignore.NewMatcher(g.patterns).Match(parts, isDir), nil
}

// split переводит абсолютный путь в сегменты относительно корня индекса;
// пустой срез — путь вне корня или сам корень.
func (g *gitignoreIndex) split(absPath string) ([]string, error) {
	rel, err := filepath.Rel(g.root, absPath)
	if err != nil {
		return nil, fmt.Errorf("relate %q to %q: %w", absPath, g.root, err)
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return []string{}, nil
	}
	return strings.Split(rel, string(filepath.Separator)), nil
}
