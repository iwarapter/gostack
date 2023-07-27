package lambstack

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_WeCanAddALambda(t *testing.T) {
	f := New()
	defer f.Close()

	input := lambda.CreateFunctionInput{
		FunctionName: aws.String("foo"),
		Code: &lambda.FunctionCode{
			ZipFile: zipTestBinary(t, "examples/simple/simple"),
		},
		Timeout: aws.Int64(5),
		Environment: &lambda.Environment{
			Variables: map[string]*string{
				"EXAMPLE": aws.String("foo"),
			},
		},
	}
	got, err := f.Add(input)
	require.NoError(t, err)
	assert.Equal(t, "arn:aws:lambda:us-east-1:123456789012:function:foo", got)
}

func Test_WeCanInvokeALambda(t *testing.T) {
	f := New()
	defer f.Close()

	input := lambda.CreateFunctionInput{
		FunctionName: aws.String("foo"),
		Code: &lambda.FunctionCode{
			ZipFile: zipTestBinary(t, "examples/simple/simple"),
		},
		Timeout: aws.Int64(5),
		Environment: &lambda.Environment{
			Variables: map[string]*string{
				"EXAMPLE": aws.String("foo"),
			},
		},
	}
	arn, err := f.Add(input)
	require.NoError(t, err)

	time.Sleep(2 * time.Second)
	resp, err := f.Invoke(arn, struct {
		Name string `json:"name"`
	}{
		Name: "unit-test",
	})

	require.NoError(t, err)
	assert.Equal(t, []byte(`"Hello unit-test!"`), resp)
}

func zipTestBinary(t *testing.T, path string) []byte {
	src, err := os.ReadFile(path)
	require.NoError(t, err)
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	hdr := &zip.FileHeader{
		Name:   "bootstrap",
		Method: zip.Deflate,
	}
	hdr.SetMode(os.ModePerm)
	dst, err := w.CreateHeader(hdr)
	require.NoError(t, err)
	_, err = io.Copy(dst, bytes.NewReader(src))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return buf.Bytes()
}
