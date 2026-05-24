/*
The MIT License (MIT)

Copyright (c) 2015-2025 V2Fly Community

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package errors

import (
	"context"
	"reflect"
	"strings"

	"github.com/exclavenetwork/exclave-core/v5/common/log"
	"github.com/exclavenetwork/exclave-core/v5/common/serial"
	"github.com/exclavenetwork/exclave-core/v5/common/session"
)

type hasSeverity interface {
	Severity() log.Severity
}

// Error is an error object with underlying error.
type Error struct {
	pathObj  interface{}
	prefix   []interface{}
	message  []interface{}
	inner    error
	severity log.Severity
}

func (err *Error) WithPathObj(obj interface{}) *Error {
	err.pathObj = obj
	return err
}

func (err *Error) pkgPath() string {
	if err.pathObj == nil {
		return ""
	}
	path := reflect.TypeOf(err.pathObj).PkgPath()
	path = strings.TrimPrefix(path, "github.com/exclavenetwork/")
	return path
}

// Error implements error.Error().
func (err *Error) Error() string {
	builder := strings.Builder{}
	for _, prefix := range err.prefix {
		builder.WriteByte('[')
		builder.WriteString(serial.ToString(prefix))
		builder.WriteString("] ")
	}

	path := err.pkgPath()
	if len(path) > 0 {
		builder.WriteString(path)
		builder.WriteString(": ")
	}

	msg := serial.Concat(err.message...)
	builder.WriteString(msg)

	if err.inner != nil {
		builder.WriteString(" > ")
		builder.WriteString(err.inner.Error())
	}

	return builder.String()
}

// Inner implements hasInnerError.Inner()
func (err *Error) Inner() error {
	if err.inner == nil {
		return nil
	}
	return err.inner
}

func (err *Error) Base(e error) *Error {
	err.inner = e
	return err
}

func (err *Error) atSeverity(s log.Severity) *Error {
	err.severity = s
	return err
}

func (err *Error) Severity() log.Severity {
	if err.inner == nil {
		return err.severity
	}

	if s, ok := err.inner.(hasSeverity); ok {
		as := s.Severity()
		if as < err.severity {
			return as
		}
	}

	return err.severity
}

// AtDebug sets the severity to debug.
func (err *Error) AtDebug() *Error {
	return err.atSeverity(log.Severity_Debug)
}

// AtInfo sets the severity to info.
func (err *Error) AtInfo() *Error {
	return err.atSeverity(log.Severity_Info)
}

// AtWarning sets the severity to warning.
func (err *Error) AtWarning() *Error {
	return err.atSeverity(log.Severity_Warning)
}

// AtError sets the severity to error.
func (err *Error) AtError() *Error {
	return err.atSeverity(log.Severity_Error)
}

// String returns the string representation of this error.
func (err *Error) String() string {
	return err.Error()
}

// WriteToLog writes current error into log.
func (err *Error) WriteToLog(opts ...ExportOption) {
	var holder ExportOptionHolder

	for _, opt := range opts {
		opt(&holder)
	}

	if holder.SessionID > 0 {
		err.prefix = append(err.prefix, holder.SessionID)
	}

	log.Record(&log.GeneralMessage{
		Severity: GetSeverity(err),
		Content:  err,
	})
}

type ExportOptionHolder struct {
	SessionID uint32
}

type ExportOption func(*ExportOptionHolder)

// New returns a new error object with message formed from given arguments.
func New(msg ...interface{}) *Error {
	return &Error{
		message:  msg,
		severity: log.Severity_Info,
	}
}

// GetSeverity returns the actual severity of the error, including inner errors.
func GetSeverity(err error) log.Severity {
	if s, ok := err.(hasSeverity); ok {
		return s.Severity()
	}
	return log.Severity_Info
}

func ExportIDToError(ctx context.Context) ExportOption {
	id := session.IDFromContext(ctx)
	return func(h *ExportOptionHolder) {
		h.SessionID = uint32(id)
	}
}
