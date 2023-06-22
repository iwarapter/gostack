package lambstack

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-lambda-go/lambda/messages"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type LambdaFactory interface {
	io.Closer
	Invoke(arn string, payload any) ([]byte, error)
	Add(input lambda.CreateFunctionInput) (string, error)
}

type lambstack struct {
	name        string
	timeout     int64
	port        int
	path        string
	environment map[string]string
	cmd         *exec.Cmd
	mu          sync.Mutex
}

func (l *lambstack) Start() error {
	l.cmd = exec.Command(fmt.Sprintf("%s/bootstrap", l.path)) //#nosec
	for key, val := range l.environment {
		l.cmd.Env = append(l.cmd.Env, fmt.Sprintf("%s=%s", key, val))
	}
	l.cmd.Env = append(l.cmd.Env, fmt.Sprintf("_LAMBDA_SERVER_PORT=%d", l.port))
	l.cmd.Env = append(l.cmd.Env, "_X_AMZN_TRACE_ID=Root=1-00000000-000000000000000000000000;Parent")
	l.cmd.Dir = l.path
	l.cmd.Stderr = log.With().Str("level", zerolog.InfoLevel.String()).Str("functionName", l.name).Logger()
	l.cmd.Stdout = l.cmd.Stderr
	return l.cmd.Start()
}

func (l *lambstack) Stop() error {
	log.Info().Str("functionName", l.name).Msg("stopping lambda")
	return l.cmd.Process.Kill()
}

func (l *lambstack) Invoke(payload any) ([]byte, error) {
	t := time.Now().Add(time.Second * time.Duration(l.timeout))
	l.mu.Lock()
	b, err := Run(Input{
		Deadline: &messages.InvokeRequest_Timestamp{
			Seconds: t.Unix(),
			Nanos:   int64(t.Nanosecond()),
		},
		Port:    l.port,
		Payload: payload,
	})
	l.mu.Unlock()
	return b, err
}

type Factory struct {
	lambdas map[string]*lambstack
}

func New() LambdaFactory {
	return &Factory{
		lambdas: map[string]*lambstack{},
	}
}

func (f *Factory) Close() error {
	log.Info().Msg("closing lambda factory")
	for _, l := range f.lambdas {
		if err := l.Stop(); err != nil {
			log.Error().Err(err).Str("name", l.name).Msg("failed to close the lambda")
		}
	}
	return nil
}

func (f *Factory) Invoke(arn string, payload any) ([]byte, error) {
	if l, ok := f.lambdas[arn]; !ok {
		return nil, fmt.Errorf("no lambstack with arn: %s", arn)
	} else {
		return l.Invoke(payload)
	}
}

func (f *Factory) Add(input lambda.CreateFunctionInput) (string, error) {
	arn := fmt.Sprintf("arn:aws:lambda:us-east-1:123456789012:function:%s", *input.FunctionName)
	if _, ok := f.lambdas[arn]; ok {
		return "", fmt.Errorf("lambda with name %s already exists", *input.FunctionName)
	}
	reader, err := zip.NewReader(bytes.NewReader(input.Code.ZipFile), int64(len(input.Code.ZipFile)))
	if err != nil {
		return "", err
	}
	dest, err := os.MkdirTemp("", *input.FunctionName)
	if err != nil {
		return "", err
	}
	// defer os.RemoveAll(dest)

	// 3. Iterate over zip files inside the archive and unzip each of them
	for _, f := range reader.File {
		err := unzipFile(f, dest)
		if err != nil {
			return "", err
		}
	}

	l, err := net.Listen("tcp", ":0") //#nosec
	if err != nil {
		return "", err
	}

	envs := map[string]string{}
	for key, val := range input.Environment.Variables {
		if val != nil {
			envs[key] = *val
		} else {
			log.Warn().Str("environment_variable", key).Msg("unable to set environment variable as value was nil")
		}
	}

	lda := &lambstack{
		name:        *input.FunctionName,
		port:        l.Addr().(*net.TCPAddr).Port,
		timeout:     *input.Timeout,
		path:        dest,
		environment: envs,
	}
	f.lambdas[arn] = lda

	return arn, lda.Start()
}

func unzipFile(f *zip.File, destination string) error {
	// 4. Check if file paths are not vulnerable to Zip Slip
	filePath := filepath.Join(destination, f.Name) //#nosec
	if !strings.HasPrefix(filePath, filepath.Clean(destination)+string(os.PathSeparator)) {
		return fmt.Errorf("invalid file path: %s", filePath)
	}

	// 5. Create directory tree
	if f.FileInfo().IsDir() {
		if err := os.MkdirAll(filePath, os.ModePerm); err != nil {
			return err
		}
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(filePath), os.ModePerm); err != nil {
		return err
	}

	// 6. Create a destination file for unzipped content
	destinationFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
	if err != nil {
		return err
	}
	defer destinationFile.Close()

	// 7. Unzip the content of a file and copy it to the destination file
	zippedFile, err := f.Open()
	if err != nil {
		return err
	}
	defer zippedFile.Close()

	for {
		_, err := io.CopyN(destinationFile, zippedFile, 1024)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
	}
	return nil
}
