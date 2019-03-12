package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	math_rand "math/rand"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/Jeffail/gabs"
	cli "github.com/jawher/mow.cli"
	uuid "github.com/satori/go.uuid"
)

var ipRand []int

// Record is a line of the CSV dump
type Record struct {
	key     []byte
	column1 []byte
	value   *gabs.Container
}

func (r Record) toCSV() string {
	var value string
	key := "0x" + hex.EncodeToString(r.key)
	column1 := "0x" + hex.EncodeToString(r.column1)
	if r.value.String() == "{}" {
		value = "null"
	} else {
		value = strconv.Quote(r.value.String())
	}
	return fmt.Sprintf(`%s,%s,%s`, key, column1, value)
}

func hash(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:32])
}

func hashFqname(fqname []string) []string {
	// fqname is of form:
	// [ domain project name uuid ]
	// [ domain project name name ]
	// [ domain project uuid ]
	// [ domain project ]
	// [ uuid ]
	// ...
	for i, c := range fqname {
		// don't hash some system resources
		if strings.HasPrefix(c, "target") || c == "default-project" || c == "default-global-system-config" {
			break
		}
		// avoid hashing uuids, some resource names
		isUUID := uuid.FromStringOrNil(c)
		if !(strings.HasPrefix(c, "default") ||
			strings.HasPrefix(c, "ingress") ||
			strings.HasPrefix(c, "egress") ||
			isUUID != uuid.UUID{}) {
			fqname[i] = hash([]byte(c))
		}
	}
	return fqname
}

func anonymiseFQName(records []Record) ([]Record, error) {
	for idx, record := range records {
		fqname := strings.Split(string(record.column1), ":")
		// remove last elem which is the uuid before hashing and put it back
		hashedFqname := hashFqname(fqname[:len(fqname)-1])
		hashedFqname = append(hashedFqname, fqname[len(fqname)-1])
		record.column1 = []byte(strings.Join(hashedFqname, ":"))
		records[idx] = record
	}
	return records, nil
}

func anonymiseUUID(records []Record) ([]Record, error) {
	for _, record := range records {
		switch string(record.column1) {
		case "fq_name":
			f := record.value.Data().([]interface{})
			fqname := make([]string, len(f))
			for i, c := range f {
				fqname[i] = c.(string)
			}
			hashedFqname := hashFqname(fqname)
			record.value.Set(hashedFqname)
		case "prop:display_name":
			displayName := hash(record.value.Bytes())
			_, err := record.value.Set(displayName)
			if err != nil {
				return records, err
			}
		case "prop:floating_ip_address":
			// randomize last 3 octets of public IPs
			ip := strings.Split(record.value.Data().(string), ".")
			for i := 1; i <= 3; i++ {
				o, _ := strconv.Atoi(ip[i])
				ip[i] = strconv.Itoa(o ^ ipRand[i-1])
			}
			record.value.Set(strings.Join(ip, "."))
		}
	}
	return records, nil
}

func readCSV(input io.Reader) (records []Record, err error) {
	var (
		key     []byte
		column1 []byte
		value   *gabs.Container
	)
	r := bufio.NewScanner(input)
	for r.Scan() {
		record := strings.SplitN(r.Text(), `,`, 3)
		key, err = hex.DecodeString(strings.TrimLeft(record[0], "0x"))
		if err != nil {
			return records, err
		}
		column1, err = hex.DecodeString(strings.TrimLeft(record[1], "0x"))
		if err != nil {
			return records, err
		}
		// Some values are not surrounded with ", need to add
		// them to unquote.
		if idx := strings.Index(record[2], `"`); idx != 0 {
			record[2] = `"` + record[2] + `"`
		}
		record[2], err = strconv.Unquote(record[2])
		if err != nil {
			return records, err
		}
		value, err = gabs.ParseJSON([]byte(record[2]))
		if err != nil {
			return records, err
		}
		records = append(records, Record{key, column1, value})
	}

	return records, nil
}

func writeCSV(records []Record, output io.Writer) {
	for _, record := range records {
		_, err := output.Write([]byte(record.toCSV() + "\n"))
		if err != nil {
			log.Fatal(err)
		}
	}
}

func main() {

	app := cli.App("contrail-db-anonymise", "Anonymise contrail DB dump")
	app.Spec = "FQNAME_DUMP UUID_DUMP DST"
	var (
		fqnameDump = app.StringArg("FQNAME_DUMP", "", "FQName table CSV dump")
		uuidDump   = app.StringArg("UUID_DUMP", "", "UUID table CSV dump")
		dst        = app.StringArg("DST", "", "Destination directory")
	)
	app.Action = func() {
		var b [8]byte
		_, err := rand.Read(b[:])
		math_rand.Seed(int64(binary.LittleEndian.Uint64(b[:])))
		ipRand = make([]int, 3)
		for i := 0; i < 3; i++ {
			ipRand[i] = math_rand.Intn(255)
		}

		uuid, err := os.Open(*uuidDump)
		defer uuid.Close()
		if err != nil {
			log.Fatal(err)
		}
		fqname, err := os.Open(*fqnameDump)
		defer fqname.Close()
		if err != nil {
			log.Fatal(err)
		}
		uuidAnon, err := os.Create(path.Join(*dst, path.Base(*uuidDump)))
		defer uuidAnon.Close()
		if err != nil {
			log.Fatal(err)
		}
		fqnameAnon, err := os.Create(path.Join(*dst, path.Base(*fqnameDump)))
		defer fqnameAnon.Close()
		if err != nil {
			log.Fatal(err)
		}

		records, err := readCSV(fqname)
		if err != nil {
			log.Fatal(err)
		}
		records, err = anonymiseFQName(records)
		if err != nil {
			log.Fatal(err)
		}
		writeCSV(records, fqnameAnon)

		records, err = readCSV(uuid)
		if err != nil {
			log.Fatal(err)
		}
		records, err = anonymiseUUID(records)
		if err != nil {
			log.Fatal(err)
		}
		writeCSV(records, uuidAnon)
	}
	app.Run(os.Args)
}
