# PTDS_httplogparser

[![Build Status](https://travis-ci.org/ozfive/BPTDS_httplogparser.svg?branch=master)](https://ttravis-ci.org/ozfive/PTDS_httplogparser)
[![GolangCI](https://golangci.com/badges/github.com/ozfive/PTDS_httplogparser.svg)](https://golangci.com)
[![Go Report](https://goreportcard.com/badge/github.com/ozfive/PTDS_httplogparser)](https://goreportcard.com/badge/github.com/ozfive/PTDS_httplogparser)
 
Persistent Threat Detection System HTTP log parser for IIS. This system ingests the latest log file in a given directory and passes it on to a work queue in RabbitMQ for further processing by service workers.
