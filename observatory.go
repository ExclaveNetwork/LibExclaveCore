/*
Copyright (C) 2021 by nekohasekai <contact-sagernet@sekai.icu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package libexclavecore

import (
	"errors"

	"github.com/exclavenetwork/exclave-core/v5/app/observatory"
	"github.com/exclavenetwork/exclave-core/v5/features/extension"
	"github.com/golang/protobuf/proto"
)

func (instance *V2RayInstance) GetObservatoryStatus(tag string) ([]byte, error) {
	if instance.observatory == nil {
		return nil, errors.New("observatory unavailable")
	}
	observer, err := instance.observatory.GetFeaturesByTag(tag)
	if err != nil {
		return nil, err
	}
	status, err := observer.(extension.Observatory).GetObservation(nil)
	if err != nil {
		return nil, err
	}
	return proto.Marshal(status)
}

func (instance *V2RayInstance) UpdateStatus(tag string, status []byte) error {
	if instance.observatory == nil {
		return errors.New("observatory unavailable")
	}

	s := new(observatory.OutboundStatus)
	err := proto.Unmarshal(status, s)
	if err != nil {
		return err
	}

	observer, err := instance.observatory.GetFeaturesByTag(tag)
	if err != nil {
		return err
	}
	observer.(*observatory.Observer).UpdateStatus(s)
	return err
}

type ObservatoryStatusUpdateListener interface {
	OnUpdateObservatoryStatus(status []byte) error
}

func (instance *V2RayInstance) SetStatusUpdateListener(tag string, listener ObservatoryStatusUpdateListener) error {
	if listener == nil {
		observer, err := instance.observatory.GetFeaturesByTag(tag)
		if err != nil {
			return err
		}
		observer.(*observatory.Observer).StatusUpdate = nil
	} else {
		observer, err := instance.observatory.GetFeaturesByTag(tag)
		if err != nil {
			return err
		}
		observer.(*observatory.Observer).StatusUpdate = func(result *observatory.OutboundStatus) {
			status, err := proto.Marshal(result)
			if err != nil {
				newError("failed to marshal status").Base(err).AtError().WriteToLog()
			}
			err = listener.OnUpdateObservatoryStatus(status)
			if err != nil {
				newError("failed to send observatory status update").Base(err).AtError().WriteToLog()
			}
		}
	}
	return nil
}
