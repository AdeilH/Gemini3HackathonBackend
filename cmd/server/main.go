package main

import "log"

func main() {
	if err := runServer(); err != nil {
		log.Fatal(err)
	}
}
