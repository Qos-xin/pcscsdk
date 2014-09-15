/* Copyright (c) Microsoft Corporation
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
using System.IO;
using System.Linq;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Media;
using Windows.Storage;
using Windows.Storage.Streams;
using System.Threading.Tasks;
using Windows.UI.Popups;
using Windows.UI.Xaml;
using Windows.Devices.SmartCards;
using Windows.Devices.Enumeration;
using Pcsc.Common;
using System.Diagnostics;

// The Blank Page item template is documented at http://go.microsoft.com/fwlink/?LinkId=234238

namespace PcscSdkSample
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainPage : Page
    {
        private SmartCardReader CardReader = null;
        private SmartCardConnection CardConnection = null;
        private Object CardConnectionLock = new Object();

        /// <summary>
        /// MainPage Constructor
        /// </summary>
        /// <returns>None</returns>
        public MainPage()
        {
            this.InitializeComponent();

            TaskScheduler.UnobservedTaskException += TaskScheduler_UnobservedTaskException;
            Application.Current.UnhandledException += Current_UnhandledException;

            GetDevices();
        }
        #region Handling_UI
        /// <summary>
        /// Change text of UI textbox
        /// </summary>
        /// <returns>None</returns>
        private void DisplayText(string message)
        {
            Debug.WriteLine(message);
            var ignored = this.Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Normal, () =>
            {
                txtLog.Text += message + Environment.NewLine;
            });
        }

        /// <summary>
        /// Changes font color of main application banner
        /// </summary>
        /// <returns>None</returns>
        private void ChangeTextBlockFontColor(TextBlock textBlock, Windows.UI.Color color)
        {
            var ignored = this.Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Normal, () =>
            {
                textBlock.Foreground = new SolidColorBrush(color);
            });
        }
        /// <summary>
        /// Display message via dialogue box
        /// </summary>
        /// <returns>None</returns>
        public async void PopupMessage(string message)
        {
            await this.Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Normal, async () =>
            {
                var dlg = new MessageDialog(message);
                await dlg.ShowAsync();
            });
        }
        #endregion

        /// <summary>
        /// Enumerates NFC reader and registers event handlers for card added/removed
        /// </summary>
        /// <returns>None</returns>
        async private void GetDevices()
        {
            try
            {
                DeviceInformationCollection devices = await DeviceInformation.FindAllAsync(SmartCardReader.GetDeviceSelector(SmartCardReaderKind.Nfc));

                // There is a bug on some devices that were updated to WP8.1 where an NFC SmartCardReader is
                // enumerated despite that the device does not support it. As a workaround, we can do an additonal check
                // to ensure the device truly does support it.
                var workaroundDetect = await DeviceInformation.FindAllAsync("System.Devices.InterfaceClassGuid:=\"{50DD5230-BA8A-11D1-BF5D-0000F805F530}\" AND System.Devices.InterfaceEnabled:=System.StructuredQueryType.Boolean#True");

                if (workaroundDetect.Count == 0 || devices.Count == 0)
                {
                    PopupMessage("No Reader Found!");
                }

                CardReader = await SmartCardReader.FromIdAsync(devices.First().Id);

                CardReader.CardAdded += CardAdded;
                CardReader.CardRemoved += CardRemoved;
            }
            catch (Exception e)
            {
                PopupMessage("Exception: " + e.Message);
            }
        }
        /// <summary>
        /// Card added event handler gets triggered when card enters nfc field
        /// </summary>
        /// <returns>None</returns>
        public async void CardAdded(SmartCardReader sender, CardAddedEventArgs args)
        {
            try
            {
                ChangeTextBlockFontColor(TextBlock_Header, Windows.UI.Colors.Green);
                await HandleCard(args);
            }
            catch (Exception e)
            {
                PopupMessage("CardAdded Exception: " + e.Message);
            }
        }
        /// <summary>
        /// Card removed event handler gets triggered when card leaves nfc field
        /// </summary>
        /// <returns>None</returns>
        void CardRemoved(SmartCardReader sender, CardRemovedEventArgs args)
        {
            lock (CardConnectionLock)
            {
                if (CardConnection != null)
                {
                    CardConnection.Dispose();
                }
            }
            ChangeTextBlockFontColor(TextBlock_Header, Windows.UI.Colors.Red);
        }
        /// <summary>
        /// Sample code to hande a couple of different cards based on the identification process
        /// </summary>
        /// <returns>None</returns>
        private async Task HandleCard(CardAddedEventArgs args)
        {
            try
            {
                var newConnection = await args.SmartCard.ConnectAsync();
                lock (CardConnectionLock)
                {
                    if (CardConnection != null)
                    {
                        CardConnection.Dispose();
                    }
                    CardConnection = newConnection;
                }

                IccDetection cardIdentification = new IccDetection(args.SmartCard, CardConnection);
                await cardIdentification.DetectCardTypeAync();

                DisplayText("Connected to card\r\nPC/SC device class: " + cardIdentification.PcscDeviceClass.ToString() + "\r\nCard name: " + cardIdentification.PcscCardName.ToString());

                if ((cardIdentification.PcscDeviceClass == Pcsc.Common.DeviceClass.StorageClass) &&
                    (cardIdentification.PcscCardName == Pcsc.CardName.MifareUltralightC
                    || cardIdentification.PcscCardName == Pcsc.CardName.MifareUltralight
                    || cardIdentification.PcscCardName == Pcsc.CardName.MifareUltralightEV1))
                {
                    // Handle MIFARE Ultralight
                    MifareUltralight.AccessHandler mifareULAccess = new MifareUltralight.AccessHandler(CardConnection);

                    // Each read should get us 16 bytes/4 blocks, so doing
                    // 4 reads will get us all 64 bytes/16 blocks on the card
                    for (byte i = 0; i < 4; i++)
                    {
                        byte[] response = await mifareULAccess.ReadAsync((byte)(4 * i));
                        DisplayText("Block " + (4 * i).ToString() + " to Block " + (4 * i + 3).ToString() + " " + BitConverter.ToString(response));
                    }

                    byte[] responseUid = await mifareULAccess.GetUidAsync();
                    DisplayText("UID:  " + BitConverter.ToString(responseUid));
                }
                else if (cardIdentification.PcscDeviceClass == Pcsc.Common.DeviceClass.MifareDesfire)
                {
                    // Handle MIFARE DESfire
                    Desfire.AccessHandler desfireAccess = new Desfire.AccessHandler(CardConnection);
                    Desfire.CardDetails card = await desfireAccess.ReadCardDetailsAsync();

                    DisplayText("DesFire Card Details:  " + Environment.NewLine + card.ToString());
                }
                else if (cardIdentification.PcscDeviceClass == Pcsc.Common.DeviceClass.StorageClass
                    && cardIdentification.PcscCardName == Pcsc.CardName.FeliCa)
                {
                    // Handle Felica
                    DisplayText("Felica card detected");
                    var felicaAccess = new Felica.AccessHandler(CardConnection);
                    var uid = await felicaAccess.GetUidAsync();
                    DisplayText("UID:  " + BitConverter.ToString(uid));
                }
                else if (cardIdentification.PcscDeviceClass == Pcsc.Common.DeviceClass.StorageClass
                    && (cardIdentification.PcscCardName == Pcsc.CardName.MifareStandard1K || cardIdentification.PcscCardName == Pcsc.CardName.MifareStandard4K))
                {
                    // Handle MIFARE Standard/Classic
                    DisplayText("MIFARE Standard/Classic card detected");
                    var mfStdAccess = new MifareStandard.AccessHandler(CardConnection);
                    var uid = await mfStdAccess.GetUidAsync();
                    DisplayText("UID:  " + BitConverter.ToString(uid));

                    ushort maxAddress = 0;
                    switch (cardIdentification.PcscCardName)
                    {
                        case Pcsc.CardName.MifareStandard1K:
                            maxAddress = 0x3f;
                            break;
                        case Pcsc.CardName.MifareStandard4K:
                            maxAddress = 0xff;
                            break;
                    }
                    await mfStdAccess.LoadKeyAsync(MifareStandard.DefaultKeys.FactoryDefault);
                    
                    for(ushort address = 0; address <= maxAddress; address++)
                    {
                        var response = await mfStdAccess.ReadAsync(address, Pcsc.GeneralAuthenticate.GeneralAuthenticateKeyType.MifareKeyA);
                        DisplayText("Block " + address.ToString() + " " + BitConverter.ToString(response));
                    }
                }
            }
            catch (Exception e)
            {
                PopupMessage("HandleCard Exception: " + e.Message);
            }
        }
        private void Current_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            string message = e.Exception.Message;
            if (e.Exception.InnerException != null)
            {
                message += Environment.NewLine + e.Exception.InnerException.Message;
            }

            PopupMessage(message);
        }
        /// <summary>
        /// Capture any unobserved exception
        /// </summary>
        /// <returns>None</returns>
        private void TaskScheduler_UnobservedTaskException(object sender, UnobservedTaskExceptionEventArgs e)
        {
            string message = e.Exception.Message;
            if (e.Exception.InnerException != null)
            {
                message += Environment.NewLine + e.Exception.InnerException.Message;
            }

            PopupMessage(message);
        }
    }
}
