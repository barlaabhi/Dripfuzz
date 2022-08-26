# Dripfuzz 

*Dripfuzz* aims to find security flaws in the hardware network protocols like MODBUS, DNP3 etc.




## Installation

- setup python virtual environment

```shell
pip install virtualenv
git clone https://github.com/barlaabhi/Dripfuzz.git
cd Dripfuzz
virtualenv fuzz_env
source fuzz_env/bin/activate
pip install -r requirements.txt
```

## Usage
```shell
usage: Dripfuzz.py [-h] -t TARGET [-v] {dumb,mutate,generate} ...

A grammar based fuzzer for SCADA protocols

positional arguments:
  {dumb,mutate,generate}
    dumb                Apply dumb fuzzing technique
    mutate              Apply mutation based fuzzing technique
    generate            Apply generation based fuzzing technique

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        target protocol
  -v, --verbosity       Log level
```

## Features
- Dumb-Fuzzing/Brute Force: Basic Fuzzer using brute force approach
- Supports smart Fuzzing approaches:
  - Generation based
- Current fuzzes:
  - MODBUS
  - DNP3


## TODO:
- Implement mutation based approach
- Enhance the fuzzer experience
- Incorporate other protocols
