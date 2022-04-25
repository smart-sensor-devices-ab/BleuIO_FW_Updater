# Copyright 2022 Smart Sensor Devices in Sweden AB
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import time
import serial.tools.list_ports
import serial
import os
import argparse


class retData:
    buffer: str = ""
    length: int = 0
    success: bool = False
    bWritten: int = 0
    bRead: int = 0
    succNo: int = 0
    indx: int = 0
    okresp: str = ""


def WriteFile(buff, leng, mNoOfBytesWritten):
    """
    :param buff: str Data to be written to the port
    :param leng: int    No of bytes to write
    :param mNoOfBytesWritten: int   Bytes written
    :return: retData
    """
    ret = retData()
    ret.buffer = buff
    ret.length = leng
    ret.bWritten = mNoOfBytesWritten
    ret.success = False
    wrote = hComm.write(buff.encode())
    if wrote > 0:
        ret.bWritten = wrote
        ret.success = True
        return ret
    else:
        ret.bWritten = 0
        ret.success = False
        return ret


def ReadFile(buff, leng, mNoBytesRead):
    """
    :param buff: str Data to be read
    :param leng: int    No of bytes to read
    :param mNoBytesRead: int    Bytes read
    :return: retData
    """
    n = hComm.read(leng)
    ret = retData()
    ret.buffer = buff
    ret.length = leng
    ret.bRead = mNoBytesRead
    ret.success = False
    if len(n) > 0:
        ret.buffer += n.decode()
        ret.bRead = len(n)
        ret.success = True
        return ret
    elif len(n) == 0:
        print("Readfile: 0 bytes, errno=[{}]\n".format("ReadFile Error"))
        ret.bRead = 0
        return ret
    else:
        ret.bRead = 0
        print("Readfile: ERROR={}=[{}]\n".format(len(n), "ReadFile Error"))
        return ret


def write_buff(buff, leng):
    """
    :param buff: str Data to be written
    :param leng: int    No of bytes to write
    :return: retData
    """
    attempts = 0
    dNoOfBytesWritten = 0

    while True:
        rcv = WriteFile(buff, leng, dNoOfBytesWritten)
        dNoOfBytesWritten = rcv.bWritten
        if not rcv.success:
            print("HOST=[write_buff: Error from WriteFile]\n")
            break
        if attempts != 0:
            print("HOST=[write_buff: RETRY]\n")
        attempts += 1
        if (leng == dNoOfBytesWritten) or (attempts >= 3):
            break

    return dNoOfBytesWritten


def read_byte():
    """
    :return: retData
    """
    # Temporary character used for reading
    TempChar = ""
    NoBytesRead = 0
    ret = retData()
    ret.success = False
    ret.succNo = 0
    rcv = ReadFile(TempChar, 1, NoBytesRead)
    if not rcv.success:
        print("HOST=[read_byte: Error from ReadFile]\n")
        ret.buffer = "0"
        ret.succNo = 0
        return ret
    elif rcv.bRead == 1:
        ret.buffer = rcv.buffer  # Store Tempchar into buffer
        ret.succNo = 1
        return ret

    return ret


def read_line(length):
    """
    :param length: int    No of bytes to read
    :return: retData
    """
    TempChar = ""  # Temporary character used for reading
    NoBytesRead = 0
    ret = retData()
    ret.bRead = 0
    ret.indx = 0
    while True:
        rcv = ReadFile(TempChar, 1, NoBytesRead)
        NoBytesRead = rcv.bRead
        if not rcv.success:
            print("HOST=[read_line: Error from ReadFile]\n")
        elif NoBytesRead == 1:
            TempChar = rcv.buffer
            if (TempChar != "\n") and (TempChar != "\r"):
                ret.buffer[ret.indx] = TempChar
                # Store Tempchar into buffer
                ret.indx += 1
            elif ret.indx == 0:
                TempChar = "\x00"
                # avoid exit over CRLF detritus at start of line

        if (
            (NoBytesRead == 0)
            or (ret.indx == length)
            or (TempChar == "\n")
            or (TempChar == "\r")
        ):
            break

    return ret


def wait_response(retrycount, buff):
    """
    Retry reading a response from the SUOTO bootloader
    :param retrycount: int    Iterations of 100ms delay
    :param buff: str    Buffer to hold response in
    :return: retData
    """
    error = False
    retries = retrycount

    ret = retData()
    ret.success = error
    buff = ""
    m = 0
    while (
        not "OK" in buff
        or "INFO SUOUSB_IMG_STARTED" in buff
        or "INFO SUOUSB_CMP_OK" in buff
        or not m < retrycount
    ):
        buff += hComm.read(1).decode()
        if "INFO SUOUSB_IMG_STARTED" in buff:
            ret.buffer = "INFO SUOUSB_IMG_STARTED"
            break
        if "INFO SUOUSB_CMP_OK" in buff:
            ret.buffer = "INFO SUOUSB_CMP_OK"
            break
        if "OK" in buff and not "INFO SUOUSB_CMP_OK" in buff:
            ret.buffer = "OK"
            break
        m += 1

    if not retries:
        ret.success = True

    return ret


def issue_command_get_ok(command, buff):
    """
    Retry reading a response from the SUOTO bootloader
    :param command: str    String command to issue to target
    :param buff: str    Buffer to hold response in
    :return: retData
    """
    error = False
    ret = retData()
    ret.success = error

    print("issue_command_get_ok:COMMAND: {}\n".format(command))

    wrote = write_buff(command, len(command))
    error = False if (len(command) == wrote) else True

    if error:
        print("issue_command_get_ok: sent:{} wrote:{}\n".format(len(command), wrote))
        return ret

    print("issue_command_get_ok: WAIT\n")

    rcv = wait_response(100, buff)
    error = rcv.success
    buff = rcv.buffer
    if not error:
        if not ("OK" in buff):
            print("issue_command_get_ok: NO, got [{}]\n".format(buff))
            error = True
        else:
            print("issue_command_get_ok: YES, got [{}]\n".format(buff))
            ret.buffer = buff
            ret.success = error

    return ret


def wait_for_specific_response_or_abort(response, retrycount, buff):
    """
    Confirms expected response - abort SUOUSB process if mismatch
    :param response: str    String expected in response from target
    :param retrycount: int  Iterations of 100ms delay
    :param buff: str    Buffer to hold response in
    :return: retData
    """
    suousb_mem_dev_abort = (
        "SUOUSB_MEM_DEV 0 4 000000FF\n"  # { 0xFF, 0x00, 0x00, 0x00 };
    )

    rcv = wait_response(retrycount, buff)
    error = rcv.success
    buff = rcv.buffer
    if not error:
        if not (buff == response):
            print("wait_for_specific_response_or_abort: FAIL=[{}]\n".format(buff))
            write_buff(suousb_mem_dev_abort, len(suousb_mem_dev_abort))
            error = True
    else:
        print("wait_for_specific_response_or_abort: TIMEOUT\n")
        write_buff(suousb_mem_dev_abort, len(suousb_mem_dev_abort))
    return error


def nibble2asciibyte(c):
    """
    Given an ASCII character, returns hex nibble value
    :param c: str    Value 0x0 to 0x0F
    :return: ('0'-'9', or 'A'-'F')
    """
    return hex(c).replace("0x", "").upper()


def do_firmware_update(imagebuf, size, suousbbuffsz):
    """
    :param imagebuf: str
    :param size: int
    :param suousbbuffsz: int
    :return: error: bool
    """
    wrote = 0
    xfered = 0
    error = False
    buff = []
    leng = 0
    ret = retData()
    strbuff = ""
    hexbuff = ""
    ret.success = False
    chunksz = suousbbuffsz / 2
    # two chunks per buffer (had problem with one chunk per buffer)

    #  Table 3: SUOUSB_MEM_DEV definition for SUOUSB mode
    #  Byte    Description
    #  3       This is the Most Significant Byte. Values:
    #  0x00 to 0x11: Reserved
    #  0x12: Image is stored in I2C EEPROM
    #  0x13: Image is stored in SPI FLASH
    #  0x14 to 0xFC: Reserved
    #  0xFD: SUOUSB reboot command. Reboot Immediately
    #  0xFE: SUOUSB end command. Indicates that image transfer has been completed..
    #  0xFF: SUOUSB abort command. Return to normal application.
    #  2       0x00
    #  1       0x00
    #  0       If byte #3 is 0x12 or 0x13 then it is the image bank:
    #  0x00: oldest
    #  0x01: Image #1
    #  0x02: Image #1
    #  Otherwise it must be equal to 0x00

    # LSB first though...
    suousb_mem_dev_start = "SUOUSB_MEM_DEV 0 4 00000013\n"
    suousb_mem_dev_reset = (
        "SUOUSB_MEM_DEV 0 4 000000FD\n"  # { 0xFD, 0x00, 0x00, 0x00 };
    )
    suousb_mem_dev_end = "SUOUSB_MEM_DEV 0 4 000000FE\n"  # { 0xFE, 0x00, 0x00, 0x00 };
    suousb_mem_dev_abort = (
        "SUOUSB_MEM_DEV 0 4 000000FF\n"  # { 0xFF, 0x00, 0x00, 0x00 };
    )

    #  Table 4: SUOUSB_GPIO_MAP definition
    #  Byte    Description
    #  3       This byte can be:
    #  1. Byte #2 of Device Address (MSB) if I2C EEPROM
    #  2. MISO position on the I/O ports if SPI FLASH
    #  2       This byte can be:
    #  1. Byte #1 of Device Address if I2C EEPROM
    #  2. MOSI position on the I/O ports if SPI FLASH
    #  1       This byte can be:
    #  1. SCL position on the GPIO ports if I2C EEPROM
    #  2. CS position on the I/O ports if SPI FLASH
    #  0       This byte can be:
    #  1. SDA position on the GPIO ports if I2C EEPROM
    #  2. SCK position on the I/O ports if SPI FLASH

    #  ProDK   board - SPI flash - MISO:P0_2  MOSI:P0_1  CS:P0_5  SCK:P0_0 - 0x02, 0x01, 0x05, 0x00

    suousb_gpio_map_prodk = "SUOUSB_GPIO_MAP 0 4 00050102\n"
    # ProDK
    # SUOUSB_PATCH_LEN = []  # i.e. "SUOUSB_PATCH_LEN 0 2 xxxx\n", will fabricate
    suousb_write_status_ena_ntfy = "SUOUSB_WRITE_STATUS 0 2 0100\n"

    if size < 64:  # ensure big enough to have a header! (user not insane)
        return True

    if (
        suousbbuffsz / 2
    ) < 64:  # ensure header can fit in single buffer (target not insane)
        return True

    strbuff = ""  # for complete CLI command to write data
    hexbuff = ""  # for hex conversion bit

    # START UPDATE PROCESS
    print("do_firmware_update: start work\n")

    rcv = issue_command_get_ok(suousb_write_status_ena_ntfy, buff)
    rcv.buffer
    rcv.success
    ret.success = rcv.success
    error = rcv.success
    if error:
        print("Failure to get ok command \n")
        return ret

    # SUOUSB_MEM_DEV        Initiator defines the Memory type (SPI or EEPROM) and the bank selection
    error = (
        False
        if (
            len(suousb_mem_dev_start)
            == write_buff(suousb_mem_dev_start, len(suousb_mem_dev_start))
        )
        else True
    )
    if error:
        print("Failure at write_buff\n")
        ret.success = error
        return ret

    # Wait for SUOUSB_SERV_STATUS=SUOUSB_IMG_STARTED
    error = wait_for_specific_response_or_abort("INFO SUOUSB_IMG_STARTED", 300, buff)
    if error:
        print("Failure at INFO SUOUSB_IMG_STARTED\n")
        ret.success = error
        return ret

    # Wait for the SUOUSB_PATCH_DATA response OK
    error = wait_for_specific_response_or_abort("OK", 300, buff)
    if error:
        print("Failure at SUOUSB_PATCH_DATA response\n")
        ret.success = error
        return ret

    # SUOUSB_GPIO_MAP       Initiator defines the mapping of the signal on GPIOs
    rcv = issue_command_get_ok(suousb_gpio_map_prodk, buff)
    error = rcv.success
    if error:
        print("Error in issue_command_get_ok\n")
        ret.success = error
        return ret

    # Set size of blocks for main bulk of update
    if (size - xfered) > suousbbuffsz:
        # SUOUSB_PATCH_LEN      Initiator defines the length of the Block size to be applied
        #                      Receiver stores the transmitted length in a temporary variable
        first = hex(suousbbuffsz & 0xFF).replace("0x", "")
        second = hex((suousbbuffsz >> 8) & 0xFF).replace("0x", "")
        if len(first) != 2:
            first = "0" + first
        if len(second) != 2:
            second = "0" + second
        SUOUSB_PATCH_LEN = "SUOUSB_PATCH_LEN 0 2 {}{}\n".format(
            first,
            second,
        )
        rcv = issue_command_get_ok(SUOUSB_PATCH_LEN, buff)
        error = rcv.success
        if error:
            print("Error in issue_command_get_ok\n")
            ret.success = error
            return ret

    # Perform main bulk of update

    while (size - int(xfered)) > suousbbuffsz:
        n = 0
        m = 0
        print(
            "do_firmware_update: send {} byte block {} * {} chunks) @ {}\n".format(
                suousbbuffsz, int(suousbbuffsz / chunksz), int(chunksz), xfered
            )
        )

        for n in range(int(suousbbuffsz / chunksz)):
            if error:
                break
            if not n < (suousbbuffsz / chunksz):
                break
            # SUOUSB_PATCH_DATA * X
            hexbuff = ""
            for m in range(int(chunksz)):
                c = imagebuf[int(xfered) + m]
                hexbuff += nibble2asciibyte(c >> 4)
                hexbuff += nibble2asciibyte(c & 0xF)
            strbuff = "SUOUSB_PATCH_DATA 0 {} {}\n".format(int(chunksz), hexbuff)
            error = (
                False if (len(strbuff) == write_buff(strbuff, len(strbuff))) else True
            )
            if error:
                break
            xfered += int(chunksz)

        error = wait_for_specific_response_or_abort("INFO SUOUSB_CMP_OK", 300, buff)
        if error:
            break

    print(
        "do_firmware_update: end {} byte block processing - {} - remainder:{}\n".format(
            suousbbuffsz, ("ERROR" if error else "OK"), (size - xfered)
        )
    )

    if error:
        print("Error in do_firmware_update\n")
        return error

    # Set new block size to remainder
    if size - xfered:
        print("do_firmware_update: set up block size {}\n".format((size - xfered)))

        # SUOUSB_PATCH_LEN      Initiator defines the length of the Last Block size (if different) to be applied
        #                      Receiver stores the new block size
        first = hex((size - xfered) & 0xFF).replace("0x", "")
        second = hex(((size - xfered) >> 8) & 0xFF).replace("0x", "")
        if len(first) != 2:
            first = "0" + first
        if len(second) != 2:
            second = "0" + second

        SUOUSB_PATCH_LEN = "SUOUSB_PATCH_LEN 0 2 {}{}\n".format(
            first,
            second,
        )
        rcv = issue_command_get_ok(SUOUSB_PATCH_LEN, buff)
        error = rcv.success
        if error:
            print(
                "do_firmware_update: set up block size {} - {}\n".format(
                    (size - xfered), ("ERROR" if error else "OK")
                )
            )
            return error
        else:
            print(
                "do_firmware_update: set up block size {} - {}\n".format(
                    (size - xfered), ("ERROR" if error else "OK")
                )
            )

    # Perform transfer of remainder
    if size - xfered:
        n = 0
        m = 0
        print(
            "do_firmware_update: send {} byte block @ {}\n".format(
                (size - xfered), xfered
            )
        )

        # Do all the chunksz byte packets we can
        while not error and (int(size - xfered) >= int(chunksz)):
            # SUOUSB_PATCH_DATA * Y
            hexbuff = ""
            for m in range(int(chunksz)):
                c = imagebuf[int(xfered + m)]
                hexbuff += nibble2asciibyte(c >> 4)
                hexbuff += nibble2asciibyte(c & 0xF)

            strbuff = "SUOUSB_PATCH_DATA 0 {} {}\n".format(int(chunksz), hexbuff)
            error = (
                False if (len(strbuff) == write_buff(strbuff, len(strbuff))) else True
            )
            xfered += int(chunksz)
            # Then deal with any <chunksz bytes remainder
        if not error and (size - xfered):
            rlen = size - xfered
            # SUOUSB_PATCH_DATA * Y
            hexbuff = ""
            for m in range(int(rlen)):
                c = imagebuf[int(xfered + m)]
                hexbuff += nibble2asciibyte(c >> 4)
                hexbuff += nibble2asciibyte(c & 0xF)

            strbuff = "SUOUSB_PATCH_DATA 0 {} {}\n".format(int(rlen), hexbuff)
            error = (
                False if (len(strbuff) == write_buff(strbuff, len(strbuff))) else True
            )
            xfered += int(rlen)

        if error:
            print("Error in do_firmware_update\n")
            return error

            # Wait for SUOUSB_SERV_STATUS=OK
        error = wait_for_specific_response_or_abort("INFO SUOUSB_CMP_OK", 3000, buff)

    print(
        "do_firmware_update: end last block processing - [{}] - remainder:{}\n".format(
            ("ERROR" if error else "OK"), (size - xfered)
        )
    )

    if error:
        print("Error in do_firmware_update\n")
        return error

    # SUOUSB_MEM_INFO       Initiator requests the total number of bytes received by receiver
    #                      4 Bytes of Data
    #                      (Total number of received bytes)
    #
    # Check size matches, if not abort update
    rl = ""
    t = 0
    hComm.write("SUOUSB_READ_MEMINFO 0 1 00\n".encode())
    while not "OK " in rl and t < 100:
        rl = hComm.readline().decode()
        time.sleep(0.001)
        t += 1
    if "OK" in rl:
        buff = rl
        buff = buff.replace("\r", "")
        buff = buff.replace("\n", "")
        rl = rl.replace("OK ", "")
        recieved_len = rl
        error = False
    else:
        error = True

    if not error:
        length = int(recieved_len)

        if length != size:
            print("ERROR from SUOUSB_READ_MEMINFO\n")
            print("len?=[{}]\n".format(length))

            write_buff(suousb_mem_dev_abort, len(suousb_mem_dev_abort))
            error = True
        else:
            print(
                "do_firmware_update: SUOUSB_READ_MEMINFO size ok {} {} [{}]\n".format(
                    size, length, buff
                )
            )
    else:
        print("do_firmware_update: SUOUSB_READ_MEMINFO error\n")
        return error

    # SUOUSB_MEM_DEV - End of transfer (0xFE000000)
    print("do_firmware_update: send suousb_mem_dev_end\n")

    error = (
        False
        if (
            len(suousb_mem_dev_end)
            == write_buff(suousb_mem_dev_end, len(suousb_mem_dev_end))
        )
        else True
    )
    if error:
        print("do_firmware_update: suousb_mem_dev_end error\n")
        return error

    # Wait for SUOUSB_SERV_STATUS=OK - Receiver verifies image checksum and writes image header
    print("do_firmware_update: wait SUOUSB_CMP_OK\n")
    error = wait_for_specific_response_or_abort("INFO SUOUSB_CMP_OK", 300, buff)
    if error:
        print("do_firmware_update: SUOUSB_CMP_OK error\n")
        return error

    # SUOUSB_MEM_DEV - System Reboot Command
    print("do_firmware_update: send suousb_mem_dev_reset\n")
    error = (
        False
        if (
            len(suousb_mem_dev_reset)
            == write_buff(suousb_mem_dev_reset, len(suousb_mem_dev_reset))
        )
        else True
    )
    if error:
        print("do_firmware_update: suousb_mem_dev_reset error\n")

    print("do_firmware_update: STOP\n")

    return error


# Main
def Main():
    parser = argparse.ArgumentParser(
        "Choose .img file to update BleuIO with (eg. bleuio.2.1.4_Release.img)"
    )
    parser.add_argument("firmware_path", default=None)
    parser.add_argument("-dbg", "--debug", action="store_true", help="shows debug msg")
    args = parser.parse_args()
    firmware = args.firmware_path
    firmware_size = 0
    HOST_PYTHON_USB_UPDATER_VERSION = 1.0
    print(
        "BleuIO Python Firmare Updater v. {}\nCopyright © 2022 BleuIO. A product of Smart Sensor Devices\n".format(
            HOST_PYTHON_USB_UPDATER_VERSION
        )
    )

    debug_msg = False
    if args.debug:
        debug_msg = True

    while True:
        exitCode = 1
        try:
            master_array = []
            index = 1
            print("Please insert the dongle you want to update...\n\n")

            while len(master_array) == 0:

                m_ports = serial.tools.list_ports.comports(include_links=False)
                for port in m_ports:
                    if str(port.hwid).__contains__("VID:PID=2DCF"):
                        master = str(index) + ") " + port.device + " " + port.hwid
                        if master.__contains__("VID:PID=2DCF:6001"):
                            print(
                                "Found BleuIO in port: "
                                + port.device
                                + " (Bootloader COM open)"
                            )
                            master_array.append(master)
                            dongle_port = port
                            index += 1
                            break
                        if master.__contains__("VID:PID=2DCF:6002"):
                            print(
                                "Found BleuIO in port: "
                                + port.device
                                + " (Application COM open)"
                            )
                            print("Opening Bootloader COM port...")
                            dongle_port = port
                            try:
                                dongle_conn = serial.Serial(
                                    dongle_port.device,
                                    115200,
                                    timeout=1,
                                )
                                if not dongle_conn.is_open:
                                    dongle_conn.open()
                                dongle_conn.write("ATR\r".encode())
                                dongle_conn.close()
                                master_array = []
                                index = 1
                                time.sleep(1)
                            except Exception as e:
                                if debug_msg:
                                    print(
                                        "Cannot access Bootloader COM port! Retrying...\n(Exception: {}".format(
                                            e
                                        )
                                    )
                                else:
                                    print(
                                        "Cannot access Bootloader COM port! Retrying..."
                                    )
                                master_array = []
                                index = 1
                            break
                    else:
                        index += 1
            print("\r\nList of Dongles:")
            for dongle in master_array:
                print(dongle)

            time.sleep(0.5)
            dongle_conn = serial.Serial(
                dongle_port.device,
                115200,
                timeout=0.05,
                write_timeout=0.5,
                rtscts=True,
                dsrdtr=True,
                xonxoff=True,
                parity=serial.PARITY_NONE,
            )

            print("Connecting to Bootloader COM Port...")
            if not dongle_conn.is_open:
                dongle_conn.open()
            global hComm
            hComm = dongle_conn

            print("Firmware File to update BleuIO with: {}\n".format(firmware))
            print(
                "HOST_PYTHON_USB_UPDATER_VERSION = {} \n".format(
                    HOST_PYTHON_USB_UPDATER_VERSION
                )
            )
            print("=== Try loading firmware image ===\n")

            firmware_file_ok = True

            try:
                firmware_size = os.stat(firmware).st_size
                if firmware_size == 0:
                    return exitCode
                actual = 0x00
                fp = open(firmware, "rb")  # 512 * 2**10
                actual = fp.read(512 * 2 ** 10)
                fp.close()
            except Exception as e:
                if debug_msg:
                    print("Cannot open Firmware file...\n(Exception: {}".format(e))
                else:
                    print("Cannot open Firmware file...")
                firmware_file_ok = False

            if firmware_file_ok:
                print("=== Try to perform USB firmware update ===\n")

                c = ""
                hComm.write("\n".encode())
                while c != ">":
                    c = hComm.read(1).decode()
                    time.sleep(0.001)
                hComm.write("getsuousbbuffsz\r".encode())
                print("HOST=[issue_command: INFO - sent: getsuousbbuffsz]\n")
                rl = ""
                while not "OK " in rl:
                    rl = hComm.readline().decode()
                    time.sleep(0.001)
                rl = rl.replace("OK ", "")
                suousbbuffsz = int(rl)
                rl = "alloc " + str(int(rl) / 2)
                rl = rl.replace(".0", "")
                rl = (rl + "\r").encode()
                hComm.write(rl)
                print("HOST=[issue_command: INFO - sent: {}]\n".format(rl.decode()))
                time.sleep(0.01)
                c = ""
                while not "OK" in c:
                    c = hComm.readline().decode()
                    time.sleep(0.01)
                hComm.write("fwupdate\r".encode())
                print("HOST=[issue_command: INFO - sent: fwupdate]\n")
                time.sleep(0.01)
                hComm.write("\n".encode())
                c = ""
                while not "OK" in c:
                    c = hComm.readline().decode()
                    time.sleep(0.01)

            exitCode = 1 if do_firmware_update(actual, len(actual), suousbbuffsz) else 0

            dongle_conn.close()
        except Exception as e:
            if debug_msg:
                print("(Exception: {}".format(e))
            exitCode = 1
        print("Result:{}\n".format("Pass" if exitCode == 0 else "Fail"))
        if exitCode == 0:
            print(
                ">>SUCCESS!<<\nThe dongle has now been updated with {}".format(firmware)
            )
            print("Verifying. Please wait...")
            time.sleep(5)
            checked_dongle_fw = False
            timeout = 0
            dongle_resp = ""
            while not checked_dongle_fw or timeout > 10:
                m_ports = serial.tools.list_ports.comports(include_links=False)
                for port in m_ports:
                    if str(port.hwid).__contains__("VID:PID=2DCF"):
                        master = str(index) + ") " + port.device + " " + port.hwid
                        if master.__contains__("VID:PID=2DCF:6002"):
                            print(
                                "Found BleuIO in port: "
                                + port.device
                                + " (Application COM open)"
                            )
                            dongle_port = port
                            try:
                                time.sleep(1)
                                dongle_conn = serial.Serial(
                                    dongle_port.device,
                                    115200,
                                    timeout=1,
                                )
                                if not dongle_conn.is_open:
                                    dongle_conn.open()
                                dongle_conn.write("ATI\r".encode())
                                read_tries = 0
                                while (
                                    not "Firmware Version: " in dongle_resp
                                    and read_tries < 10
                                ):
                                    dongle_resp = dongle_conn.readline().decode()
                                    read_tries += 1
                                    time.sleep(0.1)
                                checked_dongle_fw = True
                                dongle_conn.close()
                            except Exception as e:
                                if debug_msg:
                                    print(
                                        "Could not open COM port! Retrying...\n(Exception: {}".format(
                                            e
                                        )
                                    )
                                else:
                                    print("Could not open COM port! Retrying...")
                                checked_dongle_fw = False
                                time.sleep(1)
                            break
                    else:
                        time.sleep(0.5)
                        timeout += 1
            print("\n")
            print("*" * 100)
            if dongle_resp:
                dongle_resp = dongle_resp.replace("\r", "")
                dongle_resp = dongle_resp.replace("\n", "")
                dongle_resp = dongle_resp.replace("Firmware Version: ", "")
                print("BleuIO Firmware version is {}".format(dongle_resp))
                if dongle_resp in firmware:
                    print(
                        "BleuIO Firmware version ({}) match with name of image file ({})!".format(
                            dongle_resp, firmware
                        )
                    )
                else:
                    print(
                        "BleuIO Firmware version ({}) doesn't match with name of image file ({})!".format(
                            dongle_resp, firmware
                        )
                    )
            else:
                print("Could not verify BleuIO version.")
        else:
            print(
                ">>FAILURE!<<\nSomething went wrong with the update. Please try again."
            )
        print("*" * 100)
        run_again = input(
            "\nRun again? (y/n)\n>> " if exitCode == 0 else "\nTry again? (y/n)\n>> "
        )
        if run_again.upper().__contains__("Y"):
            continue
        else:
            exit()


if __name__ == "__main__":
    Main()