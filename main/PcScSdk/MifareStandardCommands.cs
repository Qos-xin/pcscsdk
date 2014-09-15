﻿/* Copyright (c) Microsoft Corporation
 * 
 * All rights reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 * 
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
 * 
 * See the Apache Version 2.0 License for specific language governing permissions and limitations under the License.
*/
using System;

namespace MifareStandard
{
    /// <summary>
    /// Mifare Standard Read commad when sent to the card the card is expected to return 16 bytes
    /// </summary>
    public class Read : Pcsc.ReadBinary
    {
        public Read(ushort address)
            : base(address, 16)
        {
        }
    }
    /// <summary>
    /// Mifare Standard Write commad when sent to the card, writes 16 bytes at a time
    /// </summary>
    public class Write : Pcsc.UpdateBinary
    {
        public byte[] Data
        {
            set { base.CommandData = ((value.Length != 16) ? ResizeArray(value, 16) : value); }
            get { return base.CommandData; }
        }
        private static byte[] ResizeArray(byte[] data, int size)
        {
            Array.Resize<byte>(ref data, size);
            return data;
        }
        public Write(byte address, ref byte[] data)
            : base(address, ((data.Length != 16) ? ResizeArray(data, 16) : data))
        {
        }
    }
    /// <summary>
    /// Mifare Standard GetUid command
    /// </summary>
    public class GetUid : Pcsc.GetUid
    {
        public GetUid()
            : base()
        {
        }
    }
    /// <summary>
    /// Mifare Standard GetHistoricalBytes command
    /// </summary>
    public class GetHistoricalBytes : Pcsc.GetHistoricalBytes
    {
        public GetHistoricalBytes()
            : base()
        {
        }
    }
    /// <summary>
    /// Mifare Standard Load Keys commad which stores the supplied key into the specified numbered key slot
    /// for subsequent use by the General Authenticate command.
    /// </summary>
    public class LoadKey : Pcsc.LoadKeys
    {
        public LoadKey(byte[] mifareKey, byte keySlotNumber)
            : base(LoadKeysKeyType.CardKey, null, LoadKeysTransmissionType.Plain, LoadKeysStorageType.Volatile, keySlotNumber, mifareKey)
        {
        }
    }
    /// <summary>
    /// Mifare Standard GetHistoricalBytes command
    /// </summary>
    public class GeneralAuthenticate : Pcsc.GeneralAuthenticate
    {
        public GeneralAuthenticate(ushort address, byte keySlotNumber, GeneralAuthenticateKeyType keyType)
            : base(GeneralAuthenticateVersionNumber.VersionOne, address, keyType, keySlotNumber)
        {
            if (keyType != GeneralAuthenticateKeyType.MifareKeyA && keyType != GeneralAuthenticateKeyType.PicoTagPassKeyB)
            {
                throw new Exception("Invalid key type for MIFARE Standard General Authenticate");
            }
        }
    }
    /// <summary>
    /// Mifare response APDU
    /// </summary>
    public class ApduResponse : Pcsc.ApduResponse
    {
        public ApduResponse()
            : base()
        {
        }
    }
}
