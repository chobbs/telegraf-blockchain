# Blockchain Input plugin

This experimental socket listener plugin for Influxdata/Telegraf that uses the Cryptowerk blockchain-as-a-service (BaaS) to
listen for IoT messages over (udp) and create an immutable seal on each event received.

With these digital seals, any IoT event can now be matched to its original to verify proof
of integrity. This plugin should be used for demo purposes only.

## Quick start

1. Signup for a [Crypotwerk account](https://cryptowerk.com/)  
```
Get free developer account: https://developers.cryptowerk.com/platform/portal/register.html?p=Trial
```

2. Checkout  telegraf
```
$ go get github.com/influxdata/telegraf
```

3. Checkout this repository and copy goldilocks directory to telegraf
```
$ git clone https://github.com/chobbs/telegraf-blockchain.git
$ cd telegraf-blockchain
$ cp -R cryptowerk $GOPATH/src/github.com/influxdata/telegraf/plugin/inputs
```

4. Add plugin

```
$ echo  "import  _ \"github.com/influxdata/telegraf/plugins/inputs/cryptowerk\" " >> $GOPATH/src/github.com/influxdata/telegraf/plugin/inputs/all/all.go

```

5. Build

```
$ cd $GOPATH/src/github.com/influxdata/telegraf
$ make
```

6. Getting configurations

You can get telegraf and all plugins configurations into a single config file by issuing a following command.
```
$ ./telegraf config  > telegraf.conf
```
you can find input.cryptowerk section, and uncomment the section.


## Configuration of Cryptowerk plugin

Use the following configuration for experimentation with this plugin.

```toml
# Cryptowerk blockchain event sealing.
[[inputs.cryptowerk]]
  ## Use the following service address type for this experimental plugin.
  # service_address = "udp://:8094"

  ## Cryptowerk register endpoint posts a hash of the IoT event for registration on a blockchain.
  ## The blockchain entry can later be used as a mathematical proof for the existence
  ## of this data at the moment it was posted.
  # endpoint_address = "https://developers.cryptowerk.com/platform/API/v6/register"

  ## Concatenation of Cryptowerk apiKey and apiSecret (seperated by a blank space) required.
  # auth_creds = "apikey apiSecret"

  ## Maximum socket buffer size in bytes.
  ## For stream sockets, once the buffer fills up, the sender will start backing up.
  ## For datagram sockets, once the buffer fills up, metrics will start dropping.
  ## Defaults to the OS default.
  # read_buffer_size = 65535

  ## Data format to consume.
  ## Each data format has its own unique set of configuration options, read
  ## more about them here:
  ## https://github.com/influxdata/telegraf/blob/master/docs/DATA_FORMATS_INPUT.md
  # data_format = "influx"
```

### Measurements & Fields:

Cryptowerk demo plugin creates one measurement named "cryptowerk", and will (add) 2 new fields
to any IoT event metric being collected:

- cryptohash ## This is a hash of the event metrics that get registration on a blockchain. This entry
can later be used as a mathematical proof for the existence of this data at the moment it was posted.

- retrievalid ## This a uniqueID can be used to verify the existence of a sealed event  on the blockchain (see /verify)

### Example Output:

```
> cryptowerk,deviceID=device-1,host=my-host,location=us-north,status=on temp=109,cryptohash="28c091d68a1f8df7d87124de123789bb10c62205811f3b14f43ed8ad1e724ad9",retrievalid="ri3156361f7a3698093f667bda81a9e3199b0349f57d4feae1b3f2031f80dd2384a",energy=315 1546604563961330000
```
