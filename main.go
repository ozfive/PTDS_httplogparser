/*
	
	Author: Christopher Straight

	Version: 0.0.1

	License: GPL v2.0

	Name: Analemma

	Description: Persistent Threat Detection System HTTP log parser for IIS. 
	This system ingests the latest log file in a given directory and passes 
	it on to a Work Queue in RabbitMQ for further processing by service 
	workers.

	This file is part of the Persistant Threat Detection System software (PTDS).

	PTDS is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 2 of the License, or
	(at your option) any later version.

	PTDS is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with Foobar.  If not, see <https://www.gnu.org/licenses/>.

*/
package main

import (
	"fmt"
	"log"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/hpcloud/tail"
	"github.com/streadway/amqp"
)

func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
		panic(fmt.Sprintf("%s: %s", msg, err))
	}
}

// GetLatestFile(dir string) Ensure that the file that we are reading is the latest */
func GetLatestFile(dir string) string {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var modTime time.Time
	var names []string
	for _, fi := range files {
		if fi.Mode().IsRegular() {
			if !fi.ModTime().Before(modTime) {
				if fi.ModTime().After(modTime) {
					modTime = fi.ModTime()
					names = names[:0]
				}
				names = append(names, fi.Name())
			}
		}
	}
	if len(names) > 0 {
		return names[0]
	}
	return ""
}

func tailHTTPLog() {
	
	conn, err := amqp.Dial("amqp://user:password@192.168.1.1:5672/")
	
	failOnError(err, "Failed to connect to RabbitMQ")

	defer conn.Close()

	ch, err := conn.Channel()
	failOnError(err, "Failed to open a channel.")
	defer ch.Close()

	q, err := ch.QueueDeclare(
		"client_ips", // name
		true,         // durable
		false,        //delete when unused
		false,        // exclusive
		false,        // no-wait
		nil,          // arguments
	)

	failOnError(err, "Failed to declare a queue.")

	// C:\\inetpub\\logs\\AdvancedLogs\\
	t, err := tail.TailFile("C:\\inetpub\\logs\\LogFiles\\W3SVC3\\"+GetLatestFile("C:\\inetpub\\logs\\LogFiles\\W3SVC3\\"), tail.Config{ReOpen: true, MustExist: false, Follow: true, Poll: true})
	for line := range t.Lines {
		tokens := strings.Split(line.Text, " ")
		if strings.HasPrefix(tokens[0], "#") == true {

		} else {
			// fmt.Println(tokens[0], tokens[1])
			msgBody := tokens[8]
			body := msgBody
			err = ch.Publish(
				"",     // exchange
				q.Name, // routing key
				false,  // mandatory
				false,
				amqp.Publishing{
					DeliveryMode: amqp.Persistent,
					ContentType:  "text/plain",
					Body:         []byte(body),
				})
			failOnError(err, "Failed to publish a message")
			// log.Printf("[x] Sent %s", body)
			fmt.Printf(tokens[8] + "\n\n")
		}

	}
	if err != nil {
		return
	}

}

func main() {

	// Tails the IIS realtime access log
	tailHTTPLog()

}
