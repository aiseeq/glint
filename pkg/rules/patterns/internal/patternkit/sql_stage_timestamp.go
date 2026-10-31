package patternkit

import (
	"go/token"
)

// PosAt returns the source position of an offset in the text: exact in a raw
// string, the literal's own position in an interpreted one.
func (l SqlLiteral) PosAt(offset int) token.Pos {
	for _, piece := range l.pieces {
		if offset < piece.start || offset >= piece.end {
			continue
		}
		if piece.raw {
			return piece.pos + 1 + token.Pos(offset-piece.start)
		}
		return piece.pos
	}
	if len(l.pieces) == 0 {
		return token.NoPos
	}
	return l.pieces[0].pos
}
