package main

import (
	"fmt"
	"math/rand"
	"time"
)

func main() {
	//create secret nunber
	secret := getRandomNumber()
	// fmt.Println(secret)

	for matching := false; !matching; {
		//Get user input
		guess := getUserInput()
		// fmt.Println(secret, guess)

		//Maje comparison (secret vs guess)
		matching = isMatching(secret, guess)
		fmt.Println(matching)
	}

}

func isMatching(secret, guess int) bool {
	if guess > secret {
		fmt.Println("Your guess is bigger than the secret number. Try again")
		return false
	} else if guess < secret {
		fmt.Println("Your guess is smaller than the secret number. Try again")
		return false
	} else {
		fmt.Println("Correct, you Legend!")
		return true
	}
}

func getUserInput() int {
	fmt.Printf("Please input your guess: ")
	var input int
	_, err := fmt.Scan(&input)
	if err != nil {
		fmt.Println("Failed to parse your input")
	} else {
		fmt.Println("You guess:", input)
	}
	return input
}

func getRandomNumber() int {
	rand.Seed(time.Now().Unix())
	return rand.Int() % 11
}
