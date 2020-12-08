// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Contains various wrappers for primitive types.

package mobile

import (
	"errors"
	"fmt"
)

var (
	outOfBound = errors.New("Out of bound index")
)

// Strings represents s slice of strs.
type Strings struct{ strs []string }

// Size returns the number of strs in the slice.
func (s *Strings) Size() int          { return len(s.strs) }
func (s *Strings) GetArray() []string { return s.strs }
func (s *Strings) Append(str string)  { s.strs = append(s.strs, str) }
func (s *Strings) String() string     { return fmt.Sprintf("%v", s.strs) }

// Get returns the string at the given index from the slice.
func (s *Strings) Get(index int) (str string, _ error) {
	if index < 0 || index >= len(s.strs) {
		return "", outOfBound
	}
	return s.strs[index], nil
}

// Set sets the string at the given index in the slice.
func (s *Strings) Set(index int, str string) error {
	if index < 0 || index >= len(s.strs) {
		return outOfBound
	}
	s.strs[index] = str
	return nil
}

type LongArr struct{ longs []int64 }

func (l *LongArr) Size() int         { return len(l.longs) }
func (l *LongArr) GetArray() []int64 { return l.longs }
func (l *LongArr) Append(n int64)    { l.longs = append(l.longs, n) }

func (l *LongArr) Get(index int) (int64, error) {
	if index < 0 || index >= len(l.longs) {
		return 0, outOfBound
	}
	return l.longs[index], nil
}

func (l *LongArr) Set(index int, n int64) error {
	if index < 0 || index >= len(l.longs) {
		return outOfBound
	}
	l.longs[index] = n
	return nil
}
