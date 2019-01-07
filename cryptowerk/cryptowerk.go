package cryptowerk

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"net/http"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"net/url"
	"github.com/influxdata/telegraf"
	tlsint "github.com/influxdata/telegraf/internal/tls"
	"github.com/influxdata/telegraf/plugins/inputs"
	"github.com/influxdata/telegraf/plugins/parsers"
)

type setReadBufferer interface {
	SetReadBuffer(bytes int) error
}

type packetSocketListener struct {
	net.PacketConn
	*SocketListener
}

func (psl *packetSocketListener) listen() {
	buf := make([]byte, 64*1024) // 64kb - maximum size of IP packet
	for {
		n, _, err := psl.ReadFrom(buf)
		if err != nil {
			if !strings.HasSuffix(err.Error(), ": use of closed network connection") {
				psl.AddError(err)
			}
			break
		}

		metrics, err := psl.Parse(buf[:n])
		if err != nil {
			psl.AddError(fmt.Errorf("unable to parse incoming packet: %s", err))
			//TODO rate limit
			continue
		}
		hashValue := SHA256(string(buf[:n]))
		retrievalId, err := registerToBlockchain(string(hashValue), psl.EndpointAddress, psl.AuthCredentials)

		if err != nil {
			psl.AddError(fmt.Errorf("Error from Cryptowerk registration: %s", err))
			continue
		}

		for _, m := range metrics {
		  m.AddField("cryptohash", hashValue)
			m.AddField("retrievalid", retrievalId)
			psl.AddFields(m.Name(), m.Fields(), m.Tags(), m.Time())
		}
	}
}

type Cryptowerk struct {
	MaxSupportedAPIVersion int `json:"maxSupportedAPIVersion"`
	Documents              []struct {
		RetrievalID string `json:"retrievalId"`
	} `json:"documents"`
	MinSupportedAPIVersion int `json:"minSupportedAPIVersion"`
}

func SHA256(text string) string {
	algorithm := sha256.New()
	return stringHasher(algorithm, text)
}

func stringHasher(algorithm hash.Hash, text string) string {
	algorithm.Write([]byte(text))
	return hex.EncodeToString(algorithm.Sum(nil))
}

func registerToBlockchain(buf_hash string, cryptowerk_api string, cryptowerk_key string) (retrievalId string, err error) {

	headers := map[string][]string{
			"Accept": []string{"application/json"},
			"X-API-Key": []string{cryptowerk_key},

	}

	data := url.Values{}
	data.Set("version", "6")
	data.Add("hashes", buf_hash)

	req, err := http.NewRequest("POST", cryptowerk_api, bytes.NewBufferString(data.Encode()))
	req.Header = headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value") // This makes it work


	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("cryptowerk responded with error %d", err)
	}

  defer resp.Body.Close()
	//fmt.Println("response Status:", resp.Status)
	//fmt.Println("response Headers:", resp.Header)

	// Successful responses will always return status code 200
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("cryptowerk responded with unexepcted status code %d", resp.StatusCode)
	}

	seals := &Cryptowerk{}
	if err := json.NewDecoder(resp.Body).Decode(seals); err != nil {
		return "", fmt.Errorf("unable to decode Cryptowerk response: %s", err)
	}

	registerID := seals.Documents[0].RetrievalID

	return registerID, nil
}


type SocketListener struct {
	ServiceAddress  string             `toml:"service_address"`
	EndpointAddress string             `toml:"endpoint_address"`
	AuthCredentials string             `toml:"auth_creds"`
	ReadBufferSize  int                `toml:"read_buffer_size"`
	tlsint.ServerConfig

	parsers.Parser
	telegraf.Accumulator
	io.Closer
}


func (sl *SocketListener) Description() string {
	return "Cryptowerk blockchain event sealing."
}

func (sl *SocketListener) SampleConfig() string {
	return `
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
`
}

func (sl *SocketListener) Gather(_ telegraf.Accumulator) error {
	return nil
}

func (sl *SocketListener) SetParser(parser parsers.Parser) {
	sl.Parser = parser
}

func (sl *SocketListener) Start(acc telegraf.Accumulator) error {
	sl.Accumulator = acc
	spl := strings.SplitN(sl.ServiceAddress, "://", 2)
	if len(spl) != 2 {
		return fmt.Errorf("invalid service address: %s", sl.ServiceAddress)
	}

	if spl[0] == "udp" {
		pc, err := net.ListenPacket(spl[0], spl[1])
		if err != nil {
			return err
		}
			if sl.ReadBufferSize > 0 {
				if srb, ok := pc.(setReadBufferer); ok {
					srb.SetReadBuffer(sl.ReadBufferSize)
				} else {
					log.Printf("W! Unable to set read buffer on a %s socket", spl[0])
				}
			}

			psl := &packetSocketListener{
				PacketConn:     pc,
				SocketListener: sl,
			}

			sl.Closer = psl
			go psl.listen()
		} else {
			return fmt.Errorf("unknown protocol '%s' specified in '%s'", spl[0], sl.ServiceAddress)

		}

	return nil
}

func (sl *SocketListener) Stop() {
	if sl.Closer != nil {
		sl.Close()
		sl.Closer = nil
	}
}

func newSocketListener() *SocketListener {
	parser, _ := parsers.NewInfluxParser()

	return &SocketListener{
		Parser: parser,
	}
}

func init() {
	inputs.Add("cryptowerk", func() telegraf.Input { return newSocketListener() })
}
