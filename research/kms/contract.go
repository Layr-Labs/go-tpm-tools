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
	ABI: "[{\"type\":\"constructor\",\"inputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"addBaseImage\",\"inputs\":[{\"name\":\"mrtd\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"rtmr0\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"rtmr1\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"allowedBaseImages\",\"inputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"computeKey\",\"inputs\":[{\"name\":\"mrtd\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"rtmr0\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"rtmr1\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"isAllowed\",\"inputs\":[{\"name\":\"mrtd\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"rtmr0\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"rtmr1\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"owner\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"removeBaseImage\",\"inputs\":[{\"name\":\"mrtd\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"rtmr0\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"rtmr1\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"transferOwnership\",\"inputs\":[{\"name\":\"newOwner\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"event\",\"name\":\"BaseImageAdded\",\"inputs\":[{\"name\":\"key\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"},{\"name\":\"mrtd\",\"type\":\"bytes\",\"indexed\":false,\"internalType\":\"bytes\"},{\"name\":\"rtmr0\",\"type\":\"bytes\",\"indexed\":false,\"internalType\":\"bytes\"},{\"name\":\"rtmr1\",\"type\":\"bytes\",\"indexed\":false,\"internalType\":\"bytes\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"BaseImageRemoved\",\"inputs\":[{\"name\":\"key\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"OwnershipTransferred\",\"inputs\":[{\"name\":\"previousOwner\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"newOwner\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"error\",\"name\":\"NOT_OWNER\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"ZERO_ADDRESS\",\"inputs\":[]}]",
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

// AllowedBaseImages is a free data retrieval call binding the contract method 0xcb332a2d.
//
// Solidity: function allowedBaseImages(bytes32 ) view returns(bool)
func (_BaseImageAllowlist *BaseImageAllowlistCaller) AllowedBaseImages(opts *bind.CallOpts, arg0 [32]byte) (bool, error) {
	var out []interface{}
	err := _BaseImageAllowlist.contract.Call(opts, &out, "allowedBaseImages", arg0)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// AllowedBaseImages is a free data retrieval call binding the contract method 0xcb332a2d.
//
// Solidity: function allowedBaseImages(bytes32 ) view returns(bool)
func (_BaseImageAllowlist *BaseImageAllowlistSession) AllowedBaseImages(arg0 [32]byte) (bool, error) {
	return _BaseImageAllowlist.Contract.AllowedBaseImages(&_BaseImageAllowlist.CallOpts, arg0)
}

// AllowedBaseImages is a free data retrieval call binding the contract method 0xcb332a2d.
//
// Solidity: function allowedBaseImages(bytes32 ) view returns(bool)
func (_BaseImageAllowlist *BaseImageAllowlistCallerSession) AllowedBaseImages(arg0 [32]byte) (bool, error) {
	return _BaseImageAllowlist.Contract.AllowedBaseImages(&_BaseImageAllowlist.CallOpts, arg0)
}

// ComputeKey is a free data retrieval call binding the contract method 0x3d04c00c.
//
// Solidity: function computeKey(bytes mrtd, bytes rtmr0, bytes rtmr1) pure returns(bytes32)
func (_BaseImageAllowlist *BaseImageAllowlistCaller) ComputeKey(opts *bind.CallOpts, mrtd []byte, rtmr0 []byte, rtmr1 []byte) ([32]byte, error) {
	var out []interface{}
	err := _BaseImageAllowlist.contract.Call(opts, &out, "computeKey", mrtd, rtmr0, rtmr1)

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// ComputeKey is a free data retrieval call binding the contract method 0x3d04c00c.
//
// Solidity: function computeKey(bytes mrtd, bytes rtmr0, bytes rtmr1) pure returns(bytes32)
func (_BaseImageAllowlist *BaseImageAllowlistSession) ComputeKey(mrtd []byte, rtmr0 []byte, rtmr1 []byte) ([32]byte, error) {
	return _BaseImageAllowlist.Contract.ComputeKey(&_BaseImageAllowlist.CallOpts, mrtd, rtmr0, rtmr1)
}

// ComputeKey is a free data retrieval call binding the contract method 0x3d04c00c.
//
// Solidity: function computeKey(bytes mrtd, bytes rtmr0, bytes rtmr1) pure returns(bytes32)
func (_BaseImageAllowlist *BaseImageAllowlistCallerSession) ComputeKey(mrtd []byte, rtmr0 []byte, rtmr1 []byte) ([32]byte, error) {
	return _BaseImageAllowlist.Contract.ComputeKey(&_BaseImageAllowlist.CallOpts, mrtd, rtmr0, rtmr1)
}

// IsAllowed is a free data retrieval call binding the contract method 0x86cbc80e.
//
// Solidity: function isAllowed(bytes mrtd, bytes rtmr0, bytes rtmr1) view returns(bool)
func (_BaseImageAllowlist *BaseImageAllowlistCaller) IsAllowed(opts *bind.CallOpts, mrtd []byte, rtmr0 []byte, rtmr1 []byte) (bool, error) {
	var out []interface{}
	err := _BaseImageAllowlist.contract.Call(opts, &out, "isAllowed", mrtd, rtmr0, rtmr1)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsAllowed is a free data retrieval call binding the contract method 0x86cbc80e.
//
// Solidity: function isAllowed(bytes mrtd, bytes rtmr0, bytes rtmr1) view returns(bool)
func (_BaseImageAllowlist *BaseImageAllowlistSession) IsAllowed(mrtd []byte, rtmr0 []byte, rtmr1 []byte) (bool, error) {
	return _BaseImageAllowlist.Contract.IsAllowed(&_BaseImageAllowlist.CallOpts, mrtd, rtmr0, rtmr1)
}

// IsAllowed is a free data retrieval call binding the contract method 0x86cbc80e.
//
// Solidity: function isAllowed(bytes mrtd, bytes rtmr0, bytes rtmr1) view returns(bool)
func (_BaseImageAllowlist *BaseImageAllowlistCallerSession) IsAllowed(mrtd []byte, rtmr0 []byte, rtmr1 []byte) (bool, error) {
	return _BaseImageAllowlist.Contract.IsAllowed(&_BaseImageAllowlist.CallOpts, mrtd, rtmr0, rtmr1)
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

// AddBaseImage is a paid mutator transaction binding the contract method 0x164ea9ec.
//
// Solidity: function addBaseImage(bytes mrtd, bytes rtmr0, bytes rtmr1) returns()
func (_BaseImageAllowlist *BaseImageAllowlistTransactor) AddBaseImage(opts *bind.TransactOpts, mrtd []byte, rtmr0 []byte, rtmr1 []byte) (*types.Transaction, error) {
	return _BaseImageAllowlist.contract.Transact(opts, "addBaseImage", mrtd, rtmr0, rtmr1)
}

// AddBaseImage is a paid mutator transaction binding the contract method 0x164ea9ec.
//
// Solidity: function addBaseImage(bytes mrtd, bytes rtmr0, bytes rtmr1) returns()
func (_BaseImageAllowlist *BaseImageAllowlistSession) AddBaseImage(mrtd []byte, rtmr0 []byte, rtmr1 []byte) (*types.Transaction, error) {
	return _BaseImageAllowlist.Contract.AddBaseImage(&_BaseImageAllowlist.TransactOpts, mrtd, rtmr0, rtmr1)
}

// AddBaseImage is a paid mutator transaction binding the contract method 0x164ea9ec.
//
// Solidity: function addBaseImage(bytes mrtd, bytes rtmr0, bytes rtmr1) returns()
func (_BaseImageAllowlist *BaseImageAllowlistTransactorSession) AddBaseImage(mrtd []byte, rtmr0 []byte, rtmr1 []byte) (*types.Transaction, error) {
	return _BaseImageAllowlist.Contract.AddBaseImage(&_BaseImageAllowlist.TransactOpts, mrtd, rtmr0, rtmr1)
}

// RemoveBaseImage is a paid mutator transaction binding the contract method 0x6d89e342.
//
// Solidity: function removeBaseImage(bytes mrtd, bytes rtmr0, bytes rtmr1) returns()
func (_BaseImageAllowlist *BaseImageAllowlistTransactor) RemoveBaseImage(opts *bind.TransactOpts, mrtd []byte, rtmr0 []byte, rtmr1 []byte) (*types.Transaction, error) {
	return _BaseImageAllowlist.contract.Transact(opts, "removeBaseImage", mrtd, rtmr0, rtmr1)
}

// RemoveBaseImage is a paid mutator transaction binding the contract method 0x6d89e342.
//
// Solidity: function removeBaseImage(bytes mrtd, bytes rtmr0, bytes rtmr1) returns()
func (_BaseImageAllowlist *BaseImageAllowlistSession) RemoveBaseImage(mrtd []byte, rtmr0 []byte, rtmr1 []byte) (*types.Transaction, error) {
	return _BaseImageAllowlist.Contract.RemoveBaseImage(&_BaseImageAllowlist.TransactOpts, mrtd, rtmr0, rtmr1)
}

// RemoveBaseImage is a paid mutator transaction binding the contract method 0x6d89e342.
//
// Solidity: function removeBaseImage(bytes mrtd, bytes rtmr0, bytes rtmr1) returns()
func (_BaseImageAllowlist *BaseImageAllowlistTransactorSession) RemoveBaseImage(mrtd []byte, rtmr0 []byte, rtmr1 []byte) (*types.Transaction, error) {
	return _BaseImageAllowlist.Contract.RemoveBaseImage(&_BaseImageAllowlist.TransactOpts, mrtd, rtmr0, rtmr1)
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

// BaseImageAllowlistBaseImageAddedIterator is returned from FilterBaseImageAdded and is used to iterate over the raw logs and unpacked data for BaseImageAdded events raised by the BaseImageAllowlist contract.
type BaseImageAllowlistBaseImageAddedIterator struct {
	Event *BaseImageAllowlistBaseImageAdded // Event containing the contract specifics and raw log

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
func (it *BaseImageAllowlistBaseImageAddedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(BaseImageAllowlistBaseImageAdded)
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
		it.Event = new(BaseImageAllowlistBaseImageAdded)
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
func (it *BaseImageAllowlistBaseImageAddedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *BaseImageAllowlistBaseImageAddedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// BaseImageAllowlistBaseImageAdded represents a BaseImageAdded event raised by the BaseImageAllowlist contract.
type BaseImageAllowlistBaseImageAdded struct {
	Key   [32]byte
	Mrtd  []byte
	Rtmr0 []byte
	Rtmr1 []byte
	Raw   types.Log // Blockchain specific contextual infos
}

// FilterBaseImageAdded is a free log retrieval operation binding the contract event 0xed30e352379a0bbaf6f2cd2c93ec2353aa210c21771120a15243792968f04127.
//
// Solidity: event BaseImageAdded(bytes32 indexed key, bytes mrtd, bytes rtmr0, bytes rtmr1)
func (_BaseImageAllowlist *BaseImageAllowlistFilterer) FilterBaseImageAdded(opts *bind.FilterOpts, key [][32]byte) (*BaseImageAllowlistBaseImageAddedIterator, error) {

	var keyRule []interface{}
	for _, keyItem := range key {
		keyRule = append(keyRule, keyItem)
	}

	logs, sub, err := _BaseImageAllowlist.contract.FilterLogs(opts, "BaseImageAdded", keyRule)
	if err != nil {
		return nil, err
	}
	return &BaseImageAllowlistBaseImageAddedIterator{contract: _BaseImageAllowlist.contract, event: "BaseImageAdded", logs: logs, sub: sub}, nil
}

// WatchBaseImageAdded is a free log subscription operation binding the contract event 0xed30e352379a0bbaf6f2cd2c93ec2353aa210c21771120a15243792968f04127.
//
// Solidity: event BaseImageAdded(bytes32 indexed key, bytes mrtd, bytes rtmr0, bytes rtmr1)
func (_BaseImageAllowlist *BaseImageAllowlistFilterer) WatchBaseImageAdded(opts *bind.WatchOpts, sink chan<- *BaseImageAllowlistBaseImageAdded, key [][32]byte) (event.Subscription, error) {

	var keyRule []interface{}
	for _, keyItem := range key {
		keyRule = append(keyRule, keyItem)
	}

	logs, sub, err := _BaseImageAllowlist.contract.WatchLogs(opts, "BaseImageAdded", keyRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(BaseImageAllowlistBaseImageAdded)
				if err := _BaseImageAllowlist.contract.UnpackLog(event, "BaseImageAdded", log); err != nil {
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

// ParseBaseImageAdded is a log parse operation binding the contract event 0xed30e352379a0bbaf6f2cd2c93ec2353aa210c21771120a15243792968f04127.
//
// Solidity: event BaseImageAdded(bytes32 indexed key, bytes mrtd, bytes rtmr0, bytes rtmr1)
func (_BaseImageAllowlist *BaseImageAllowlistFilterer) ParseBaseImageAdded(log types.Log) (*BaseImageAllowlistBaseImageAdded, error) {
	event := new(BaseImageAllowlistBaseImageAdded)
	if err := _BaseImageAllowlist.contract.UnpackLog(event, "BaseImageAdded", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// BaseImageAllowlistBaseImageRemovedIterator is returned from FilterBaseImageRemoved and is used to iterate over the raw logs and unpacked data for BaseImageRemoved events raised by the BaseImageAllowlist contract.
type BaseImageAllowlistBaseImageRemovedIterator struct {
	Event *BaseImageAllowlistBaseImageRemoved // Event containing the contract specifics and raw log

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
func (it *BaseImageAllowlistBaseImageRemovedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(BaseImageAllowlistBaseImageRemoved)
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
		it.Event = new(BaseImageAllowlistBaseImageRemoved)
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
func (it *BaseImageAllowlistBaseImageRemovedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *BaseImageAllowlistBaseImageRemovedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// BaseImageAllowlistBaseImageRemoved represents a BaseImageRemoved event raised by the BaseImageAllowlist contract.
type BaseImageAllowlistBaseImageRemoved struct {
	Key [32]byte
	Raw types.Log // Blockchain specific contextual infos
}

// FilterBaseImageRemoved is a free log retrieval operation binding the contract event 0xf4713b228d42c646654f1bd87ae0fc23334bc998c67d2bca232a36bafc4e74cd.
//
// Solidity: event BaseImageRemoved(bytes32 indexed key)
func (_BaseImageAllowlist *BaseImageAllowlistFilterer) FilterBaseImageRemoved(opts *bind.FilterOpts, key [][32]byte) (*BaseImageAllowlistBaseImageRemovedIterator, error) {

	var keyRule []interface{}
	for _, keyItem := range key {
		keyRule = append(keyRule, keyItem)
	}

	logs, sub, err := _BaseImageAllowlist.contract.FilterLogs(opts, "BaseImageRemoved", keyRule)
	if err != nil {
		return nil, err
	}
	return &BaseImageAllowlistBaseImageRemovedIterator{contract: _BaseImageAllowlist.contract, event: "BaseImageRemoved", logs: logs, sub: sub}, nil
}

// WatchBaseImageRemoved is a free log subscription operation binding the contract event 0xf4713b228d42c646654f1bd87ae0fc23334bc998c67d2bca232a36bafc4e74cd.
//
// Solidity: event BaseImageRemoved(bytes32 indexed key)
func (_BaseImageAllowlist *BaseImageAllowlistFilterer) WatchBaseImageRemoved(opts *bind.WatchOpts, sink chan<- *BaseImageAllowlistBaseImageRemoved, key [][32]byte) (event.Subscription, error) {

	var keyRule []interface{}
	for _, keyItem := range key {
		keyRule = append(keyRule, keyItem)
	}

	logs, sub, err := _BaseImageAllowlist.contract.WatchLogs(opts, "BaseImageRemoved", keyRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(BaseImageAllowlistBaseImageRemoved)
				if err := _BaseImageAllowlist.contract.UnpackLog(event, "BaseImageRemoved", log); err != nil {
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

// ParseBaseImageRemoved is a log parse operation binding the contract event 0xf4713b228d42c646654f1bd87ae0fc23334bc998c67d2bca232a36bafc4e74cd.
//
// Solidity: event BaseImageRemoved(bytes32 indexed key)
func (_BaseImageAllowlist *BaseImageAllowlistFilterer) ParseBaseImageRemoved(log types.Log) (*BaseImageAllowlistBaseImageRemoved, error) {
	event := new(BaseImageAllowlistBaseImageRemoved)
	if err := _BaseImageAllowlist.contract.UnpackLog(event, "BaseImageRemoved", log); err != nil {
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
