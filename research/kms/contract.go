// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package main

import (
	"errors"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
	_ = abi.ConvertType
)

// BaseImageAllowlistMetaData contains all meta data concerning the BaseImageAllowlist contract.
var BaseImageAllowlistMetaData = &bind.MetaData{
	ABI: "[{\"type\":\"constructor\",\"inputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"checkSupport\",\"inputs\":[{\"name\":\"level\",\"type\":\"uint8\",\"internalType\":\"enumBaseImageAllowlist.SupportLevel\"},{\"name\":\"minimum\",\"type\":\"uint8\",\"internalType\":\"enumBaseImageAllowlist.SupportLevel\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"checkTcb\",\"inputs\":[{\"name\":\"cvm\",\"type\":\"uint8\",\"internalType\":\"enumBaseImageAllowlist.CVM\"},{\"name\":\"tcb\",\"type\":\"uint64\",\"internalType\":\"uint64\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getImageSupport\",\"inputs\":[{\"name\":\"pcr8\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"pcr9\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint8\",\"internalType\":\"enumBaseImageAllowlist.SupportLevel\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"imageSupport\",\"inputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint8\",\"internalType\":\"enumBaseImageAllowlist.SupportLevel\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"isImageAllowed\",\"inputs\":[{\"name\":\"pcr8\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"pcr9\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"minimumSupportLevel\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint8\",\"internalType\":\"enumBaseImageAllowlist.SupportLevel\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"minimumTcb\",\"inputs\":[{\"name\":\"\",\"type\":\"uint8\",\"internalType\":\"enumBaseImageAllowlist.CVM\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint64\",\"internalType\":\"uint64\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"owner\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"setImageSupport\",\"inputs\":[{\"name\":\"pcr8\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"pcr9\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"level\",\"type\":\"uint8\",\"internalType\":\"enumBaseImageAllowlist.SupportLevel\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"setMinimumSupportLevel\",\"inputs\":[{\"name\":\"newLevel\",\"type\":\"uint8\",\"internalType\":\"enumBaseImageAllowlist.SupportLevel\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"setMinimumTcb\",\"inputs\":[{\"name\":\"cvm\",\"type\":\"uint8\",\"internalType\":\"enumBaseImageAllowlist.CVM\"},{\"name\":\"newTcb\",\"type\":\"uint64\",\"internalType\":\"uint64\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"transferOwnership\",\"inputs\":[{\"name\":\"newOwner\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"event\",\"name\":\"ImageSupportUpdated\",\"inputs\":[{\"name\":\"key\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"},{\"name\":\"pcr8\",\"type\":\"bytes32\",\"indexed\":false,\"internalType\":\"bytes32\"},{\"name\":\"pcr9\",\"type\":\"bytes32\",\"indexed\":false,\"internalType\":\"bytes32\"},{\"name\":\"level\",\"type\":\"uint8\",\"indexed\":false,\"internalType\":\"enumBaseImageAllowlist.SupportLevel\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"MinimumSupportLevelUpdated\",\"inputs\":[{\"name\":\"oldLevel\",\"type\":\"uint8\",\"indexed\":false,\"internalType\":\"enumBaseImageAllowlist.SupportLevel\"},{\"name\":\"newLevel\",\"type\":\"uint8\",\"indexed\":false,\"internalType\":\"enumBaseImageAllowlist.SupportLevel\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"MinimumTcbUpdated\",\"inputs\":[{\"name\":\"cvm\",\"type\":\"uint8\",\"indexed\":true,\"internalType\":\"enumBaseImageAllowlist.CVM\"},{\"name\":\"oldTcb\",\"type\":\"uint64\",\"indexed\":false,\"internalType\":\"uint64\"},{\"name\":\"newTcb\",\"type\":\"uint64\",\"indexed\":false,\"internalType\":\"uint64\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"OwnershipTransferred\",\"inputs\":[{\"name\":\"previousOwner\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"newOwner\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"error\",\"name\":\"NOT_OWNER\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"ZERO_ADDRESS\",\"inputs\":[]}]",
}

// BaseImageAllowlistABI is the input ABI used to generate the binding from.
// Deprecated: Use BaseImageAllowlistMetaData.ABI instead.
var BaseImageAllowlistABI = BaseImageAllowlistMetaData.ABI

// BaseImageAllowlist is an auto generated Go binding around an Ethereum contract.
type BaseImageAllowlist struct {
	BaseImageAllowlistCaller     // Read-only binding to the contract
	BaseImageAllowlistTransactor // Write-only binding to the contract
	BaseImageAllowlistFilterer   // Log filterer for contract events
}

// BaseImageAllowlistCaller is an auto generated read-only Go binding around an Ethereum contract.
type BaseImageAllowlistCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// BaseImageAllowlistTransactor is an auto generated write-only Go binding around an Ethereum contract.
type BaseImageAllowlistTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// BaseImageAllowlistFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type BaseImageAllowlistFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// BaseImageAllowlistSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type BaseImageAllowlistSession struct {
	Contract     *BaseImageAllowlist // Generic contract binding to set the session for
	CallOpts     bind.CallOpts       // Call options to use throughout this session
	TransactOpts bind.TransactOpts   // Transaction auth options to use throughout this session
}

// BaseImageAllowlistCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type BaseImageAllowlistCallerSession struct {
	Contract *BaseImageAllowlistCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts             // Call options to use throughout this session
}

// BaseImageAllowlistTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type BaseImageAllowlistTransactorSession struct {
	Contract     *BaseImageAllowlistTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts             // Transaction auth options to use throughout this session
}

// BaseImageAllowlistRaw is an auto generated low-level Go binding around an Ethereum contract.
type BaseImageAllowlistRaw struct {
	Contract *BaseImageAllowlist // Generic contract binding to access the raw methods on
}

// BaseImageAllowlistCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type BaseImageAllowlistCallerRaw struct {
	Contract *BaseImageAllowlistCaller // Generic read-only contract binding to access the raw methods on
}

// BaseImageAllowlistTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type BaseImageAllowlistTransactorRaw struct {
	Contract *BaseImageAllowlistTransactor // Generic write-only contract binding to access the raw methods on
}

// NewBaseImageAllowlist creates a new instance of BaseImageAllowlist, bound to a specific deployed contract.
func NewBaseImageAllowlist(address common.Address, backend bind.ContractBackend) (*BaseImageAllowlist, error) {
	contract, err := bindBaseImageAllowlist(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &BaseImageAllowlist{BaseImageAllowlistCaller: BaseImageAllowlistCaller{contract: contract}, BaseImageAllowlistTransactor: BaseImageAllowlistTransactor{contract: contract}, BaseImageAllowlistFilterer: BaseImageAllowlistFilterer{contract: contract}}, nil
}

// NewBaseImageAllowlistCaller creates a new read-only instance of BaseImageAllowlist, bound to a specific deployed contract.
func NewBaseImageAllowlistCaller(address common.Address, caller bind.ContractCaller) (*BaseImageAllowlistCaller, error) {
	contract, err := bindBaseImageAllowlist(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &BaseImageAllowlistCaller{contract: contract}, nil
}

// NewBaseImageAllowlistTransactor creates a new write-only instance of BaseImageAllowlist, bound to a specific deployed contract.
func NewBaseImageAllowlistTransactor(address common.Address, transactor bind.ContractTransactor) (*BaseImageAllowlistTransactor, error) {
	contract, err := bindBaseImageAllowlist(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &BaseImageAllowlistTransactor{contract: contract}, nil
}

// NewBaseImageAllowlistFilterer creates a new log filterer instance of BaseImageAllowlist, bound to a specific deployed contract.
func NewBaseImageAllowlistFilterer(address common.Address, filterer bind.ContractFilterer) (*BaseImageAllowlistFilterer, error) {
	contract, err := bindBaseImageAllowlist(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &BaseImageAllowlistFilterer{contract: contract}, nil
}

// bindBaseImageAllowlist binds a generic wrapper to an already deployed contract.
func bindBaseImageAllowlist(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := BaseImageAllowlistMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_BaseImageAllowlist *BaseImageAllowlistRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _BaseImageAllowlist.Contract.BaseImageAllowlistCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_BaseImageAllowlist *BaseImageAllowlistRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _BaseImageAllowlist.Contract.BaseImageAllowlistTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_BaseImageAllowlist *BaseImageAllowlistRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _BaseImageAllowlist.Contract.BaseImageAllowlistTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_BaseImageAllowlist *BaseImageAllowlistCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _BaseImageAllowlist.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_BaseImageAllowlist *BaseImageAllowlistTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _BaseImageAllowlist.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_BaseImageAllowlist *BaseImageAllowlistTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _BaseImageAllowlist.Contract.contract.Transact(opts, method, params...)
}

// CheckSupport is a free data retrieval call binding the contract method 0x91b2aa61.
//
// Solidity: function checkSupport(uint8 level, uint8 minimum) pure returns(bool)
func (_BaseImageAllowlist *BaseImageAllowlistCaller) CheckSupport(opts *bind.CallOpts, level uint8, minimum uint8) (bool, error) {
	var out []interface{}
	err := _BaseImageAllowlist.contract.Call(opts, &out, "checkSupport", level, minimum)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// CheckSupport is a free data retrieval call binding the contract method 0x91b2aa61.
//
// Solidity: function checkSupport(uint8 level, uint8 minimum) pure returns(bool)
func (_BaseImageAllowlist *BaseImageAllowlistSession) CheckSupport(level uint8, minimum uint8) (bool, error) {
	return _BaseImageAllowlist.Contract.CheckSupport(&_BaseImageAllowlist.CallOpts, level, minimum)
}

// CheckSupport is a free data retrieval call binding the contract method 0x91b2aa61.
//
// Solidity: function checkSupport(uint8 level, uint8 minimum) pure returns(bool)
func (_BaseImageAllowlist *BaseImageAllowlistCallerSession) CheckSupport(level uint8, minimum uint8) (bool, error) {
	return _BaseImageAllowlist.Contract.CheckSupport(&_BaseImageAllowlist.CallOpts, level, minimum)
}

// CheckTcb is a free data retrieval call binding the contract method 0xa44cb94a.
//
// Solidity: function checkTcb(uint8 cvm, uint64 tcb) view returns(bool)
func (_BaseImageAllowlist *BaseImageAllowlistCaller) CheckTcb(opts *bind.CallOpts, cvm uint8, tcb uint64) (bool, error) {
	var out []interface{}
	err := _BaseImageAllowlist.contract.Call(opts, &out, "checkTcb", cvm, tcb)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// CheckTcb is a free data retrieval call binding the contract method 0xa44cb94a.
//
// Solidity: function checkTcb(uint8 cvm, uint64 tcb) view returns(bool)
func (_BaseImageAllowlist *BaseImageAllowlistSession) CheckTcb(cvm uint8, tcb uint64) (bool, error) {
	return _BaseImageAllowlist.Contract.CheckTcb(&_BaseImageAllowlist.CallOpts, cvm, tcb)
}

// CheckTcb is a free data retrieval call binding the contract method 0xa44cb94a.
//
// Solidity: function checkTcb(uint8 cvm, uint64 tcb) view returns(bool)
func (_BaseImageAllowlist *BaseImageAllowlistCallerSession) CheckTcb(cvm uint8, tcb uint64) (bool, error) {
	return _BaseImageAllowlist.Contract.CheckTcb(&_BaseImageAllowlist.CallOpts, cvm, tcb)
}

// GetImageSupport is a free data retrieval call binding the contract method 0xf5cbff9c.
//
// Solidity: function getImageSupport(bytes32 pcr8, bytes32 pcr9) view returns(uint8)
func (_BaseImageAllowlist *BaseImageAllowlistCaller) GetImageSupport(opts *bind.CallOpts, pcr8 [32]byte, pcr9 [32]byte) (uint8, error) {
	var out []interface{}
	err := _BaseImageAllowlist.contract.Call(opts, &out, "getImageSupport", pcr8, pcr9)

	if err != nil {
		return *new(uint8), err
	}

	out0 := *abi.ConvertType(out[0], new(uint8)).(*uint8)

	return out0, err

}

// GetImageSupport is a free data retrieval call binding the contract method 0xf5cbff9c.
//
// Solidity: function getImageSupport(bytes32 pcr8, bytes32 pcr9) view returns(uint8)
func (_BaseImageAllowlist *BaseImageAllowlistSession) GetImageSupport(pcr8 [32]byte, pcr9 [32]byte) (uint8, error) {
	return _BaseImageAllowlist.Contract.GetImageSupport(&_BaseImageAllowlist.CallOpts, pcr8, pcr9)
}

// GetImageSupport is a free data retrieval call binding the contract method 0xf5cbff9c.
//
// Solidity: function getImageSupport(bytes32 pcr8, bytes32 pcr9) view returns(uint8)
func (_BaseImageAllowlist *BaseImageAllowlistCallerSession) GetImageSupport(pcr8 [32]byte, pcr9 [32]byte) (uint8, error) {
	return _BaseImageAllowlist.Contract.GetImageSupport(&_BaseImageAllowlist.CallOpts, pcr8, pcr9)
}

// ImageSupport is a free data retrieval call binding the contract method 0x24847343.
//
// Solidity: function imageSupport(bytes32 ) view returns(uint8)
func (_BaseImageAllowlist *BaseImageAllowlistCaller) ImageSupport(opts *bind.CallOpts, arg0 [32]byte) (uint8, error) {
	var out []interface{}
	err := _BaseImageAllowlist.contract.Call(opts, &out, "imageSupport", arg0)

	if err != nil {
		return *new(uint8), err
	}

	out0 := *abi.ConvertType(out[0], new(uint8)).(*uint8)

	return out0, err

}

// ImageSupport is a free data retrieval call binding the contract method 0x24847343.
//
// Solidity: function imageSupport(bytes32 ) view returns(uint8)
func (_BaseImageAllowlist *BaseImageAllowlistSession) ImageSupport(arg0 [32]byte) (uint8, error) {
	return _BaseImageAllowlist.Contract.ImageSupport(&_BaseImageAllowlist.CallOpts, arg0)
}

// ImageSupport is a free data retrieval call binding the contract method 0x24847343.
//
// Solidity: function imageSupport(bytes32 ) view returns(uint8)
func (_BaseImageAllowlist *BaseImageAllowlistCallerSession) ImageSupport(arg0 [32]byte) (uint8, error) {
	return _BaseImageAllowlist.Contract.ImageSupport(&_BaseImageAllowlist.CallOpts, arg0)
}

// IsImageAllowed is a free data retrieval call binding the contract method 0xb39ed3cf.
//
// Solidity: function isImageAllowed(bytes32 pcr8, bytes32 pcr9) view returns(bool)
func (_BaseImageAllowlist *BaseImageAllowlistCaller) IsImageAllowed(opts *bind.CallOpts, pcr8 [32]byte, pcr9 [32]byte) (bool, error) {
	var out []interface{}
	err := _BaseImageAllowlist.contract.Call(opts, &out, "isImageAllowed", pcr8, pcr9)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsImageAllowed is a free data retrieval call binding the contract method 0xb39ed3cf.
//
// Solidity: function isImageAllowed(bytes32 pcr8, bytes32 pcr9) view returns(bool)
func (_BaseImageAllowlist *BaseImageAllowlistSession) IsImageAllowed(pcr8 [32]byte, pcr9 [32]byte) (bool, error) {
	return _BaseImageAllowlist.Contract.IsImageAllowed(&_BaseImageAllowlist.CallOpts, pcr8, pcr9)
}

// IsImageAllowed is a free data retrieval call binding the contract method 0xb39ed3cf.
//
// Solidity: function isImageAllowed(bytes32 pcr8, bytes32 pcr9) view returns(bool)
func (_BaseImageAllowlist *BaseImageAllowlistCallerSession) IsImageAllowed(pcr8 [32]byte, pcr9 [32]byte) (bool, error) {
	return _BaseImageAllowlist.Contract.IsImageAllowed(&_BaseImageAllowlist.CallOpts, pcr8, pcr9)
}

// MinimumSupportLevel is a free data retrieval call binding the contract method 0x2d66eee5.
//
// Solidity: function minimumSupportLevel() view returns(uint8)
func (_BaseImageAllowlist *BaseImageAllowlistCaller) MinimumSupportLevel(opts *bind.CallOpts) (uint8, error) {
	var out []interface{}
	err := _BaseImageAllowlist.contract.Call(opts, &out, "minimumSupportLevel")

	if err != nil {
		return *new(uint8), err
	}

	out0 := *abi.ConvertType(out[0], new(uint8)).(*uint8)

	return out0, err

}

// MinimumSupportLevel is a free data retrieval call binding the contract method 0x2d66eee5.
//
// Solidity: function minimumSupportLevel() view returns(uint8)
func (_BaseImageAllowlist *BaseImageAllowlistSession) MinimumSupportLevel() (uint8, error) {
	return _BaseImageAllowlist.Contract.MinimumSupportLevel(&_BaseImageAllowlist.CallOpts)
}

// MinimumSupportLevel is a free data retrieval call binding the contract method 0x2d66eee5.
//
// Solidity: function minimumSupportLevel() view returns(uint8)
func (_BaseImageAllowlist *BaseImageAllowlistCallerSession) MinimumSupportLevel() (uint8, error) {
	return _BaseImageAllowlist.Contract.MinimumSupportLevel(&_BaseImageAllowlist.CallOpts)
}

// MinimumTcb is a free data retrieval call binding the contract method 0xdf1bf33c.
//
// Solidity: function minimumTcb(uint8 ) view returns(uint64)
func (_BaseImageAllowlist *BaseImageAllowlistCaller) MinimumTcb(opts *bind.CallOpts, arg0 uint8) (uint64, error) {
	var out []interface{}
	err := _BaseImageAllowlist.contract.Call(opts, &out, "minimumTcb", arg0)

	if err != nil {
		return *new(uint64), err
	}

	out0 := *abi.ConvertType(out[0], new(uint64)).(*uint64)

	return out0, err

}

// MinimumTcb is a free data retrieval call binding the contract method 0xdf1bf33c.
//
// Solidity: function minimumTcb(uint8 ) view returns(uint64)
func (_BaseImageAllowlist *BaseImageAllowlistSession) MinimumTcb(arg0 uint8) (uint64, error) {
	return _BaseImageAllowlist.Contract.MinimumTcb(&_BaseImageAllowlist.CallOpts, arg0)
}

// MinimumTcb is a free data retrieval call binding the contract method 0xdf1bf33c.
//
// Solidity: function minimumTcb(uint8 ) view returns(uint64)
func (_BaseImageAllowlist *BaseImageAllowlistCallerSession) MinimumTcb(arg0 uint8) (uint64, error) {
	return _BaseImageAllowlist.Contract.MinimumTcb(&_BaseImageAllowlist.CallOpts, arg0)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_BaseImageAllowlist *BaseImageAllowlistCaller) Owner(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _BaseImageAllowlist.contract.Call(opts, &out, "owner")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_BaseImageAllowlist *BaseImageAllowlistSession) Owner() (common.Address, error) {
	return _BaseImageAllowlist.Contract.Owner(&_BaseImageAllowlist.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_BaseImageAllowlist *BaseImageAllowlistCallerSession) Owner() (common.Address, error) {
	return _BaseImageAllowlist.Contract.Owner(&_BaseImageAllowlist.CallOpts)
}

// SetImageSupport is a paid mutator transaction binding the contract method 0x08cba123.
//
// Solidity: function setImageSupport(bytes32 pcr8, bytes32 pcr9, uint8 level) returns()
func (_BaseImageAllowlist *BaseImageAllowlistTransactor) SetImageSupport(opts *bind.TransactOpts, pcr8 [32]byte, pcr9 [32]byte, level uint8) (*types.Transaction, error) {
	return _BaseImageAllowlist.contract.Transact(opts, "setImageSupport", pcr8, pcr9, level)
}

// SetImageSupport is a paid mutator transaction binding the contract method 0x08cba123.
//
// Solidity: function setImageSupport(bytes32 pcr8, bytes32 pcr9, uint8 level) returns()
func (_BaseImageAllowlist *BaseImageAllowlistSession) SetImageSupport(pcr8 [32]byte, pcr9 [32]byte, level uint8) (*types.Transaction, error) {
	return _BaseImageAllowlist.Contract.SetImageSupport(&_BaseImageAllowlist.TransactOpts, pcr8, pcr9, level)
}

// SetImageSupport is a paid mutator transaction binding the contract method 0x08cba123.
//
// Solidity: function setImageSupport(bytes32 pcr8, bytes32 pcr9, uint8 level) returns()
func (_BaseImageAllowlist *BaseImageAllowlistTransactorSession) SetImageSupport(pcr8 [32]byte, pcr9 [32]byte, level uint8) (*types.Transaction, error) {
	return _BaseImageAllowlist.Contract.SetImageSupport(&_BaseImageAllowlist.TransactOpts, pcr8, pcr9, level)
}

// SetMinimumSupportLevel is a paid mutator transaction binding the contract method 0x810280fe.
//
// Solidity: function setMinimumSupportLevel(uint8 newLevel) returns()
func (_BaseImageAllowlist *BaseImageAllowlistTransactor) SetMinimumSupportLevel(opts *bind.TransactOpts, newLevel uint8) (*types.Transaction, error) {
	return _BaseImageAllowlist.contract.Transact(opts, "setMinimumSupportLevel", newLevel)
}

// SetMinimumSupportLevel is a paid mutator transaction binding the contract method 0x810280fe.
//
// Solidity: function setMinimumSupportLevel(uint8 newLevel) returns()
func (_BaseImageAllowlist *BaseImageAllowlistSession) SetMinimumSupportLevel(newLevel uint8) (*types.Transaction, error) {
	return _BaseImageAllowlist.Contract.SetMinimumSupportLevel(&_BaseImageAllowlist.TransactOpts, newLevel)
}

// SetMinimumSupportLevel is a paid mutator transaction binding the contract method 0x810280fe.
//
// Solidity: function setMinimumSupportLevel(uint8 newLevel) returns()
func (_BaseImageAllowlist *BaseImageAllowlistTransactorSession) SetMinimumSupportLevel(newLevel uint8) (*types.Transaction, error) {
	return _BaseImageAllowlist.Contract.SetMinimumSupportLevel(&_BaseImageAllowlist.TransactOpts, newLevel)
}

// SetMinimumTcb is a paid mutator transaction binding the contract method 0x734a7ab6.
//
// Solidity: function setMinimumTcb(uint8 cvm, uint64 newTcb) returns()
func (_BaseImageAllowlist *BaseImageAllowlistTransactor) SetMinimumTcb(opts *bind.TransactOpts, cvm uint8, newTcb uint64) (*types.Transaction, error) {
	return _BaseImageAllowlist.contract.Transact(opts, "setMinimumTcb", cvm, newTcb)
}

// SetMinimumTcb is a paid mutator transaction binding the contract method 0x734a7ab6.
//
// Solidity: function setMinimumTcb(uint8 cvm, uint64 newTcb) returns()
func (_BaseImageAllowlist *BaseImageAllowlistSession) SetMinimumTcb(cvm uint8, newTcb uint64) (*types.Transaction, error) {
	return _BaseImageAllowlist.Contract.SetMinimumTcb(&_BaseImageAllowlist.TransactOpts, cvm, newTcb)
}

// SetMinimumTcb is a paid mutator transaction binding the contract method 0x734a7ab6.
//
// Solidity: function setMinimumTcb(uint8 cvm, uint64 newTcb) returns()
func (_BaseImageAllowlist *BaseImageAllowlistTransactorSession) SetMinimumTcb(cvm uint8, newTcb uint64) (*types.Transaction, error) {
	return _BaseImageAllowlist.Contract.SetMinimumTcb(&_BaseImageAllowlist.TransactOpts, cvm, newTcb)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_BaseImageAllowlist *BaseImageAllowlistTransactor) TransferOwnership(opts *bind.TransactOpts, newOwner common.Address) (*types.Transaction, error) {
	return _BaseImageAllowlist.contract.Transact(opts, "transferOwnership", newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_BaseImageAllowlist *BaseImageAllowlistSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _BaseImageAllowlist.Contract.TransferOwnership(&_BaseImageAllowlist.TransactOpts, newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_BaseImageAllowlist *BaseImageAllowlistTransactorSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _BaseImageAllowlist.Contract.TransferOwnership(&_BaseImageAllowlist.TransactOpts, newOwner)
}

// BaseImageAllowlistImageSupportUpdatedIterator is returned from FilterImageSupportUpdated and is used to iterate over the raw logs and unpacked data for ImageSupportUpdated events raised by the BaseImageAllowlist contract.
type BaseImageAllowlistImageSupportUpdatedIterator struct {
	Event *BaseImageAllowlistImageSupportUpdated // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *BaseImageAllowlistImageSupportUpdatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(BaseImageAllowlistImageSupportUpdated)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(BaseImageAllowlistImageSupportUpdated)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *BaseImageAllowlistImageSupportUpdatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *BaseImageAllowlistImageSupportUpdatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// BaseImageAllowlistImageSupportUpdated represents a ImageSupportUpdated event raised by the BaseImageAllowlist contract.
type BaseImageAllowlistImageSupportUpdated struct {
	Key   [32]byte
	Pcr8  [32]byte
	Pcr9  [32]byte
	Level uint8
	Raw   types.Log // Blockchain specific contextual infos
}

// FilterImageSupportUpdated is a free log retrieval operation binding the contract event 0x1abab0af3c1fef79a0a2e42617058e519c90f4f5d472c989003de284fbcb1608.
//
// Solidity: event ImageSupportUpdated(bytes32 indexed key, bytes32 pcr8, bytes32 pcr9, uint8 level)
func (_BaseImageAllowlist *BaseImageAllowlistFilterer) FilterImageSupportUpdated(opts *bind.FilterOpts, key [][32]byte) (*BaseImageAllowlistImageSupportUpdatedIterator, error) {

	var keyRule []interface{}
	for _, keyItem := range key {
		keyRule = append(keyRule, keyItem)
	}

	logs, sub, err := _BaseImageAllowlist.contract.FilterLogs(opts, "ImageSupportUpdated", keyRule)
	if err != nil {
		return nil, err
	}
	return &BaseImageAllowlistImageSupportUpdatedIterator{contract: _BaseImageAllowlist.contract, event: "ImageSupportUpdated", logs: logs, sub: sub}, nil
}

// WatchImageSupportUpdated is a free log subscription operation binding the contract event 0x1abab0af3c1fef79a0a2e42617058e519c90f4f5d472c989003de284fbcb1608.
//
// Solidity: event ImageSupportUpdated(bytes32 indexed key, bytes32 pcr8, bytes32 pcr9, uint8 level)
func (_BaseImageAllowlist *BaseImageAllowlistFilterer) WatchImageSupportUpdated(opts *bind.WatchOpts, sink chan<- *BaseImageAllowlistImageSupportUpdated, key [][32]byte) (event.Subscription, error) {

	var keyRule []interface{}
	for _, keyItem := range key {
		keyRule = append(keyRule, keyItem)
	}

	logs, sub, err := _BaseImageAllowlist.contract.WatchLogs(opts, "ImageSupportUpdated", keyRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(BaseImageAllowlistImageSupportUpdated)
				if err := _BaseImageAllowlist.contract.UnpackLog(event, "ImageSupportUpdated", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseImageSupportUpdated is a log parse operation binding the contract event 0x1abab0af3c1fef79a0a2e42617058e519c90f4f5d472c989003de284fbcb1608.
//
// Solidity: event ImageSupportUpdated(bytes32 indexed key, bytes32 pcr8, bytes32 pcr9, uint8 level)
func (_BaseImageAllowlist *BaseImageAllowlistFilterer) ParseImageSupportUpdated(log types.Log) (*BaseImageAllowlistImageSupportUpdated, error) {
	event := new(BaseImageAllowlistImageSupportUpdated)
	if err := _BaseImageAllowlist.contract.UnpackLog(event, "ImageSupportUpdated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// BaseImageAllowlistMinimumSupportLevelUpdatedIterator is returned from FilterMinimumSupportLevelUpdated and is used to iterate over the raw logs and unpacked data for MinimumSupportLevelUpdated events raised by the BaseImageAllowlist contract.
type BaseImageAllowlistMinimumSupportLevelUpdatedIterator struct {
	Event *BaseImageAllowlistMinimumSupportLevelUpdated // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *BaseImageAllowlistMinimumSupportLevelUpdatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(BaseImageAllowlistMinimumSupportLevelUpdated)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(BaseImageAllowlistMinimumSupportLevelUpdated)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *BaseImageAllowlistMinimumSupportLevelUpdatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *BaseImageAllowlistMinimumSupportLevelUpdatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// BaseImageAllowlistMinimumSupportLevelUpdated represents a MinimumSupportLevelUpdated event raised by the BaseImageAllowlist contract.
type BaseImageAllowlistMinimumSupportLevelUpdated struct {
	OldLevel uint8
	NewLevel uint8
	Raw      types.Log // Blockchain specific contextual infos
}

// FilterMinimumSupportLevelUpdated is a free log retrieval operation binding the contract event 0xbcab9955f1df90464d7e2668d7080aed00ea5b75a27894a8d51b348309ac37a0.
//
// Solidity: event MinimumSupportLevelUpdated(uint8 oldLevel, uint8 newLevel)
func (_BaseImageAllowlist *BaseImageAllowlistFilterer) FilterMinimumSupportLevelUpdated(opts *bind.FilterOpts) (*BaseImageAllowlistMinimumSupportLevelUpdatedIterator, error) {

	logs, sub, err := _BaseImageAllowlist.contract.FilterLogs(opts, "MinimumSupportLevelUpdated")
	if err != nil {
		return nil, err
	}
	return &BaseImageAllowlistMinimumSupportLevelUpdatedIterator{contract: _BaseImageAllowlist.contract, event: "MinimumSupportLevelUpdated", logs: logs, sub: sub}, nil
}

// WatchMinimumSupportLevelUpdated is a free log subscription operation binding the contract event 0xbcab9955f1df90464d7e2668d7080aed00ea5b75a27894a8d51b348309ac37a0.
//
// Solidity: event MinimumSupportLevelUpdated(uint8 oldLevel, uint8 newLevel)
func (_BaseImageAllowlist *BaseImageAllowlistFilterer) WatchMinimumSupportLevelUpdated(opts *bind.WatchOpts, sink chan<- *BaseImageAllowlistMinimumSupportLevelUpdated) (event.Subscription, error) {

	logs, sub, err := _BaseImageAllowlist.contract.WatchLogs(opts, "MinimumSupportLevelUpdated")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(BaseImageAllowlistMinimumSupportLevelUpdated)
				if err := _BaseImageAllowlist.contract.UnpackLog(event, "MinimumSupportLevelUpdated", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseMinimumSupportLevelUpdated is a log parse operation binding the contract event 0xbcab9955f1df90464d7e2668d7080aed00ea5b75a27894a8d51b348309ac37a0.
//
// Solidity: event MinimumSupportLevelUpdated(uint8 oldLevel, uint8 newLevel)
func (_BaseImageAllowlist *BaseImageAllowlistFilterer) ParseMinimumSupportLevelUpdated(log types.Log) (*BaseImageAllowlistMinimumSupportLevelUpdated, error) {
	event := new(BaseImageAllowlistMinimumSupportLevelUpdated)
	if err := _BaseImageAllowlist.contract.UnpackLog(event, "MinimumSupportLevelUpdated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// BaseImageAllowlistMinimumTcbUpdatedIterator is returned from FilterMinimumTcbUpdated and is used to iterate over the raw logs and unpacked data for MinimumTcbUpdated events raised by the BaseImageAllowlist contract.
type BaseImageAllowlistMinimumTcbUpdatedIterator struct {
	Event *BaseImageAllowlistMinimumTcbUpdated // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *BaseImageAllowlistMinimumTcbUpdatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(BaseImageAllowlistMinimumTcbUpdated)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(BaseImageAllowlistMinimumTcbUpdated)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *BaseImageAllowlistMinimumTcbUpdatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *BaseImageAllowlistMinimumTcbUpdatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// BaseImageAllowlistMinimumTcbUpdated represents a MinimumTcbUpdated event raised by the BaseImageAllowlist contract.
type BaseImageAllowlistMinimumTcbUpdated struct {
	Cvm    uint8
	OldTcb uint64
	NewTcb uint64
	Raw    types.Log // Blockchain specific contextual infos
}

// FilterMinimumTcbUpdated is a free log retrieval operation binding the contract event 0x83e88ada39bccecdbcee22fd99da923c7a1f3231b98245185bf9e93f4b1af53c.
//
// Solidity: event MinimumTcbUpdated(uint8 indexed cvm, uint64 oldTcb, uint64 newTcb)
func (_BaseImageAllowlist *BaseImageAllowlistFilterer) FilterMinimumTcbUpdated(opts *bind.FilterOpts, cvm []uint8) (*BaseImageAllowlistMinimumTcbUpdatedIterator, error) {

	var cvmRule []interface{}
	for _, cvmItem := range cvm {
		cvmRule = append(cvmRule, cvmItem)
	}

	logs, sub, err := _BaseImageAllowlist.contract.FilterLogs(opts, "MinimumTcbUpdated", cvmRule)
	if err != nil {
		return nil, err
	}
	return &BaseImageAllowlistMinimumTcbUpdatedIterator{contract: _BaseImageAllowlist.contract, event: "MinimumTcbUpdated", logs: logs, sub: sub}, nil
}

// WatchMinimumTcbUpdated is a free log subscription operation binding the contract event 0x83e88ada39bccecdbcee22fd99da923c7a1f3231b98245185bf9e93f4b1af53c.
//
// Solidity: event MinimumTcbUpdated(uint8 indexed cvm, uint64 oldTcb, uint64 newTcb)
func (_BaseImageAllowlist *BaseImageAllowlistFilterer) WatchMinimumTcbUpdated(opts *bind.WatchOpts, sink chan<- *BaseImageAllowlistMinimumTcbUpdated, cvm []uint8) (event.Subscription, error) {

	var cvmRule []interface{}
	for _, cvmItem := range cvm {
		cvmRule = append(cvmRule, cvmItem)
	}

	logs, sub, err := _BaseImageAllowlist.contract.WatchLogs(opts, "MinimumTcbUpdated", cvmRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(BaseImageAllowlistMinimumTcbUpdated)
				if err := _BaseImageAllowlist.contract.UnpackLog(event, "MinimumTcbUpdated", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseMinimumTcbUpdated is a log parse operation binding the contract event 0x83e88ada39bccecdbcee22fd99da923c7a1f3231b98245185bf9e93f4b1af53c.
//
// Solidity: event MinimumTcbUpdated(uint8 indexed cvm, uint64 oldTcb, uint64 newTcb)
func (_BaseImageAllowlist *BaseImageAllowlistFilterer) ParseMinimumTcbUpdated(log types.Log) (*BaseImageAllowlistMinimumTcbUpdated, error) {
	event := new(BaseImageAllowlistMinimumTcbUpdated)
	if err := _BaseImageAllowlist.contract.UnpackLog(event, "MinimumTcbUpdated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// BaseImageAllowlistOwnershipTransferredIterator is returned from FilterOwnershipTransferred and is used to iterate over the raw logs and unpacked data for OwnershipTransferred events raised by the BaseImageAllowlist contract.
type BaseImageAllowlistOwnershipTransferredIterator struct {
	Event *BaseImageAllowlistOwnershipTransferred // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *BaseImageAllowlistOwnershipTransferredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(BaseImageAllowlistOwnershipTransferred)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(BaseImageAllowlistOwnershipTransferred)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *BaseImageAllowlistOwnershipTransferredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *BaseImageAllowlistOwnershipTransferredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// BaseImageAllowlistOwnershipTransferred represents a OwnershipTransferred event raised by the BaseImageAllowlist contract.
type BaseImageAllowlistOwnershipTransferred struct {
	PreviousOwner common.Address
	NewOwner      common.Address
	Raw           types.Log // Blockchain specific contextual infos
}

// FilterOwnershipTransferred is a free log retrieval operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_BaseImageAllowlist *BaseImageAllowlistFilterer) FilterOwnershipTransferred(opts *bind.FilterOpts, previousOwner []common.Address, newOwner []common.Address) (*BaseImageAllowlistOwnershipTransferredIterator, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _BaseImageAllowlist.contract.FilterLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return &BaseImageAllowlistOwnershipTransferredIterator{contract: _BaseImageAllowlist.contract, event: "OwnershipTransferred", logs: logs, sub: sub}, nil
}

// WatchOwnershipTransferred is a free log subscription operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_BaseImageAllowlist *BaseImageAllowlistFilterer) WatchOwnershipTransferred(opts *bind.WatchOpts, sink chan<- *BaseImageAllowlistOwnershipTransferred, previousOwner []common.Address, newOwner []common.Address) (event.Subscription, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _BaseImageAllowlist.contract.WatchLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(BaseImageAllowlistOwnershipTransferred)
				if err := _BaseImageAllowlist.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseOwnershipTransferred is a log parse operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_BaseImageAllowlist *BaseImageAllowlistFilterer) ParseOwnershipTransferred(log types.Log) (*BaseImageAllowlistOwnershipTransferred, error) {
	event := new(BaseImageAllowlistOwnershipTransferred)
	if err := _BaseImageAllowlist.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
