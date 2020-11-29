/**
 * Written by Vy Nguyen
 */
package math

import (
	"math/big"
)

var (
	ZERO      = big.NewInt(0)
	TEN       = big.NewInt(10)
	XU_UNIT   = new(big.Int).Exp(TEN, big.NewInt(14), nil)
	HAO_UNIT  = new(big.Int).Exp(TEN, big.NewInt(16), nil)
	DONG_UNIT = new(big.Int).Exp(TEN, big.NewInt(18), nil)
	WEI       = UnitConv{new(big.Int).Exp(TEN, big.NewInt(0), nil), "wei"}
	KWEI      = UnitConv{new(big.Int).Exp(TEN, big.NewInt(3), nil), "kwei"}
	MWEI      = UnitConv{new(big.Int).Exp(TEN, big.NewInt(6), nil), "mwei"}
	GWEI      = UnitConv{new(big.Int).Exp(TEN, big.NewInt(9), nil), "gwei"}
	SZABO     = UnitConv{new(big.Int).Exp(TEN, big.NewInt(12), nil), "szabo"}
	FINNEY    = UnitConv{new(big.Int).Exp(TEN, big.NewInt(15), nil), "finney"}
	XU        = UnitConv{new(big.Int).Exp(TEN, big.NewInt(14), nil), "xu"}
	HAO       = UnitConv{new(big.Int).Exp(TEN, big.NewInt(16), nil), "hao"}
	DONG      = UnitConv{new(big.Int).Exp(TEN, big.NewInt(18), nil), "dong"}
	ETHER     = UnitConv{new(big.Int).Exp(TEN, big.NewInt(18), nil), "ether"}
	KETHER    = UnitConv{new(big.Int).Exp(TEN, big.NewInt(21), nil), "kether"}
	MEHTER    = UnitConv{new(big.Int).Exp(TEN, big.NewInt(24), nil), "mether"}
	GETHER    = UnitConv{new(big.Int).Exp(TEN, big.NewInt(27), nil), "gether"}
)

type UnitConv struct {
	Factor *big.Int
	Name   string
}

// Convert to Wei from the specified unit.
//
func ToWei(num string, unit *UnitConv) *big.Int {
	val := new(big.Int)
	if x, _ := val.SetString(num, 10); x != nil {
		return x.Mul(x, unit.Factor)
	}
	return nil
}

func ToWeiNum(x *big.Int, unit *UnitConv) *big.Int {
	return x.Mul(x, unit.Factor)
}

func XuToWei(xu int64) *big.Int {
	return ToWeiNum(big.NewInt(xu), &XU)
}

func HaoToWei(hao int64) *big.Int {
	return ToWeiNum(big.NewInt(hao), &HAO)
}

// Convert from Wei to the specified unit.
//
func FromWei(num string, unit *UnitConv) *big.Int {
	val := new(big.Int)
	if x, _ := val.SetString(num, 10); x != nil {
		return ToWeiNum(val, unit)
	}
	return nil
}

func FromWeiNum(num *big.Int, unit *UnitConv) *big.Int {
	return ToWeiNum(num, unit)
}

func FromWeiToXu(wei *big.Int) int64 {
	return new(big.Int).Div(wei, XU.Factor).Int64()
}

func FromWeiToHao(wei *big.Int) int64 {
	return new(big.Int).Div(wei, HAO.Factor).Int64()
}
