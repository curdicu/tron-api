# TRON API
A PHP API for interacting with the Tron Protocol

[![Latest Stable Version](https://poser.pugx.org/curdicu/tron-api/version)](https://packagist.org/packages/curdicu/tron-api)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE)
[![Build Status](https://api.travis-ci.com/curdicu/tron-api.svg?branch=master)](https://travis-ci.com/curdicu/tron-api)
[![Contributors](https://img.shields.io/github/contributors/curdicu/tron-api.svg)](https://github.com/curdicu/tron-api/graphs/contributors)
[![Total Downloads](https://img.shields.io/packagist/dt/curdicu/tron-api.svg?style=flat-square)](https://packagist.org/packages/curdicu/tron-api)

## Install

```bash
composer require curdicu/tron-api --ignore-platform-reqs
composer update curdicu/tron-api --ignore-platform-reqs
```
## Requirements

The following versions of PHP are supported by this version.

* PHP 7.4

## Example Usage

```php
use IEXBase\TronAPI\Tron;

$fullNode = new \IEXBase\TronAPI\Provider\HttpProvider('https://api.trongrid.io');
$solidityNode = new \IEXBase\TronAPI\Provider\HttpProvider('https://api.trongrid.io');
$eventServer = new \IEXBase\TronAPI\Provider\HttpProvider('https://api.trongrid.io');

try {
    $tron = new \IEXBase\TronAPI\Tron($fullNode, $solidityNode, $eventServer);
} catch (\IEXBase\TronAPI\Exception\TronException $e) {
    exit($e->getMessage());
}


$this->setAddress('..');
//Balance
$tron->getBalance(null, true);

// Transfer Trx
var_dump($tron->send('to', 1.5));

//Generate Address
var_dump($tron->createAccount());

//Get Last Blocks
var_dump($tron->getLatestBlocks(2));

//Change account name (only once)
var_dump($tron->changeAccountName('address', 'NewName'));


// Contract
$tron->contract('Contract Address');



```

## Testing

``` bash
$ vendor/bin/phpunit
```

