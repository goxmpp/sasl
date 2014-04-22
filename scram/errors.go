package scram

import "fmt"

type WrongClientMessage string

func (wcm WrongClientMessage) Error() string {
	return fmt.Sprintf("Wrong Client Message Provided: %s", wcm)
}

type WrongServerMessage string

func (wsm WrongServerMessage) Error() string {
	return fmt.Sprintf("Wrong Server Message Provided: %s", wsm)
}
