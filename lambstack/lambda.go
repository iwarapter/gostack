package lambstack

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/rpc"
	"time"

	"github.com/aws/aws-lambda-go/lambda/messages"
	lc "github.com/aws/aws-lambda-go/lambdacontext"
)

const functioninvokeRPC = "Function.Invoke"

type Input = struct {
	Port          int
	Payload       interface{}
	ClientContext *lc.ClientContext
	Deadline      *messages.InvokeRequest_Timestamp
}

// Run a Go based lambstack, passing the configured payload
// note that 'payload' can be anything that can be encoded by encoding/json
func Run(input Input) ([]byte, error) {
	request, err := createInvokeRequest(input)

	if err != nil {
		return nil, err
	}

	// 2. Open a TCP connection to the lambstack
	client, err := rpc.Dial("tcp", fmt.Sprintf(":%d", input.Port))
	if err != nil {
		return nil, err
	}

	// 3. Issue an RPC request for the Function.Invoke method
	var response messages.InvokeResponse

	if err = client.Call(functioninvokeRPC, request, &response); err != nil {
		return nil, err
	}

	if response.Error != nil {
		return nil, errors.New(response.Error.Message)
	}

	return response.Payload, nil
}

func createInvokeRequest(input Input) (*messages.InvokeRequest, error) {
	payloadEncoded, err := json.Marshal(input.Payload)
	if err != nil {
		return nil, err
	}

	var clientContextEncoded []byte
	if input.ClientContext != nil {
		b, err := json.Marshal(input.ClientContext)

		if err != nil {
			return nil, err
		}

		clientContextEncoded = b
	}

	Deadline := input.Deadline

	if Deadline == nil {
		t := time.Now().Add(5 * time.Second)
		Deadline = &messages.InvokeRequest_Timestamp{
			Seconds: t.Unix(),
			Nanos:   int64(t.Nanosecond()),
		}
	}

	return &messages.InvokeRequest{
		Payload:               payloadEncoded,
		RequestId:             "0",
		XAmznTraceId:          "",
		Deadline:              *Deadline,
		InvokedFunctionArn:    "",
		CognitoIdentityId:     "",
		CognitoIdentityPoolId: "",
		ClientContext:         clientContextEncoded,
	}, nil
}
