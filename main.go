package main

/*
	Copyright: Christopher Straight 2018 All rights reserved.

	Author: Christopher Straight

	Version: 0.0.1

	License: GPL v2.0

	Name: PTDS (Persistent Threat Detection System) HTTP log parser.

	Description: Persistent Threat Detection System HTTP log parser for IIS.
	This system ingests the latest log file in a given directory and passes
	it on to a work queue in RabbitMQ for further processing by service
	workers.

	This file is part of the Persistent Threat Detection System software (PTDS).

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

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	"github.com/hpcloud/tail"
	"github.com/streadway/amqp"
)

func main() {

	// Start tailing the IIS log file.
	TailHTTPLog()

}

// GetLatestFile (dir string) Ensure that the file that we are reading is
// the latest log file in the given directory.
func GetLatestFile(directory string) string {

	files, err := ioutil.ReadDir(directory)

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

// TailHTTPLog () tails the latest http log file in a given directory and
// sends individual request values to the work queue.
func TailHTTPLog() {

	conn, err := amqp.Dial("amqp://[USERNAME]:[PASSWORD][RABBITMQ SERVER IP]:[PORT]/")

	FailOnError(err, "Failed to connect to RabbitMQ")

	defer conn.Close()

	ch, err := conn.Channel()

	FailOnError(err, "Failed to open a channel.")

	defer ch.Close()

	q, err := ch.QueueDeclare(
		"client_ips", // name
		true,         // durable
		false,        //delete when unused
		false,        // exclusive
		false,        // no-wait
		nil,          // arguments
	)

	FailOnError(err, "Failed to declare a queue.")

	t, err := tail.TailFile("C:\\inetpub\\logs\\LogFiles\\W3SVC3\\"+GetLatestFile("C:\\inetpub\\logs\\LogFiles\\W3SVC3\\"),
		tail.Config{ReOpen: true, MustExist: false, Follow: true, Poll: true})

	for line := range t.Lines {

		tokens := strings.Split(line.Text, " ")

		// Ignore all lines in the log file that begin with #.
		// These lines are comments and not requests so no
		// need to pass them to the work queue.
		if strings.HasPrefix(tokens[0], "#") {
			// Do nothing with this line since it is a comment.
		} else {

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

			FailOnError(err, "Failed to publish a message")

			fmt.Printf(tokens[8] + "\n\n")
		}

	}

	if err != nil {
		return
	}
}

// FailOnError (err error, msg string) is a simple error wrapper.
func FailOnError(err error, msg string) {

	if err != nil {

		log.Fatalf("%s: %s", msg, err)
		panic(fmt.Sprintf("%s: %s", msg, err))

	}
}
