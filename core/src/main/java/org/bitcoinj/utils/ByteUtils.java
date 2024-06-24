/*
 * Copyright by the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.utils;

import com.google.common.io.BaseEncoding;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.BufferOverflowException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Comparator;

import static org.bitcoinj.utils.Preconditions.check;
import static org.bitcoinj.utils.Preconditions.checkArgument;

/**
 * Utility methods for bit, byte, and integer manipulation and conversion. Most of these were moved here
 * from {@code org.bitcoinj.core.Utils}.
 */
public class ByteUtils {

    /** Maximum unsigned value that can be expressed by 16 bits. */
    public static final int MAX_UNSIGNED_SHORT = 0xFFFF;
    /** Maximum unsigned value that can be expressed by 32 bits. */
    public static final long MAX_UNSIGNED_INTEGER = 0xFFFFFFFFL;

    private static final int[] bitMask = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};

    private static final HexFormat hexFormat = new HexFormat();

    public static String formatHex(byte[] bytes) {
        return hexFormat.formatHex(bytes);
    }

    public static byte[] parseHex(String string) {
        return hexFormat.parseHex(string);
    }

    public static byte[] bigIntegerToBytes(BigInteger b, int numBytes) {
        checkArgument(b.signum() >= 0, "b must be positive or zero: " + b);
        checkArgument(numBytes > 0, "numBytes must be positive: " + numBytes);
        byte[] src = b.toByteArray();
        byte[] dest = new byte[numBytes];
        boolean isFirstByteOnlyForSign = src[0] == 0;
        int length = isFirstByteOnlyForSign ? src.length - 1 : src.length;
        checkArgument(length <= numBytes, "The given number does not fit in " + numBytes);
        int srcPos = isFirstByteOnlyForSign ? 1 : 0;
        int destPos = numBytes - length;
        System.arraycopy(src, srcPos, dest, destPos, length);
        return dest;
    }

    public static BigInteger bytesToBigInteger(byte[] bytes) {
        return new BigInteger(1, bytes);
    }

    public static ByteBuffer writeInt16LE(int val, ByteBuffer buf) throws BufferOverflowException {
        checkArgument(val >= 0 && val <= MAX_UNSIGNED_SHORT, "value out of range: " + val);
        return buf.order(ByteOrder.LITTLE_ENDIAN).putShort((short) val);
    }

    public static ByteBuffer writeInt16BE(int val, ByteBuffer buf) throws BufferOverflowException {
        checkArgument(val >= 0 && val <= MAX_UNSIGNED_SHORT, "value out of range: " + val);
        return buf.order(ByteOrder.BIG_ENDIAN).putShort((short) val);
    }

    public static ByteBuffer writeInt32LE(int val, ByteBuffer buf) throws BufferOverflowException {
        return buf.order(ByteOrder.LITTLE_ENDIAN).putInt(val);
    }

    public static ByteBuffer writeInt32LE(long val, ByteBuffer buf) throws BufferOverflowException {
        checkArgument(val >= 0 && val <= MAX_UNSIGNED_INTEGER, "value out of range: " + val);
        return buf.order(ByteOrder.LITTLE_ENDIAN).putInt((int) val);
    }

    public static void writeInt32LE(long val, byte[] out, int offset) throws ArrayIndexOutOfBoundsException {
        checkArgument(offset >= 0 && offset <= out.length - 4, "offset out of range: " + offset);
        writeInt32LE(val, ByteBuffer.wrap(out, offset, out.length - offset));
    }

    public static ByteBuffer writeInt32BE(int val, ByteBuffer buf) throws BufferOverflowException {
        return buf.order(ByteOrder.BIG_ENDIAN).putInt(val);
    }

    public static void writeInt32BE(int val, byte[] out, int offset) throws ArrayIndexOutOfBoundsException {
        writeInt32BE(val, ByteBuffer.wrap(out, offset, out.length - offset));
    }

    public static ByteBuffer writeInt64LE(long val, ByteBuffer buf) throws BufferOverflowException {
        return buf.order(ByteOrder.LITTLE_ENDIAN).putLong(val);
    }

    public static void writeInt64LE(long val, byte[] out, int offset) throws ArrayIndexOutOfBoundsException {
        checkArgument(offset >= 0 && offset <= out.length - 8, "offset out of range: " + offset);
        writeInt64LE(val, ByteBuffer.wrap(out, offset, out.length - offset));
    }

    public static void writeInt16LE(int val, OutputStream stream) throws IOException {
        byte[] buf = new byte[2];
        writeInt16LE(val, ByteBuffer.wrap(buf));
        stream.write(buf);
    }

    public static void writeInt16BE(int val, OutputStream stream) throws IOException {
        byte[] buf = new byte[2];
        writeInt16BE(val, ByteBuffer.wrap(buf));
        stream.write(buf);
    }

    public static void writeInt32LE(int val, OutputStream stream) throws IOException {
        byte[] buf = new byte[4];
        writeInt32LE(val, ByteBuffer.wrap(buf));
        stream.write(buf);
    }

    public static void writeInt32LE(long val, OutputStream stream) throws IOException {
        byte[] buf = new byte[4];
        writeInt32LE(val, ByteBuffer.wrap(buf));
        stream.write(buf);
    }

    public static void writeInt32BE(int val, OutputStream stream) throws IOException {
        byte[] buf = new byte[4];
        writeInt32BE(val, ByteBuffer.wrap(buf));
        stream.write(buf);
    }

    public static void writeInt64LE(long val, OutputStream stream) throws IOException {
        byte[] buf = new byte[8];
        writeInt64LE(val, ByteBuffer.wrap(buf));
        stream.write(buf);
    }

    public static void writeInt64LE(BigInteger val, OutputStream stream) throws IOException {
        byte[] bytes = val.toByteArray();
        if (bytes.length > 8) {
            throw new RuntimeException("Input too large to encode into a uint64");
        }
        bytes = reverseBytes(bytes);
        stream.write(bytes);
        if (bytes.length < 8) {
            for (int i = 0; i < 8 - bytes.length; i++)
                stream.write(0);
        }
    }

    public static int readUint16(ByteBuffer buf) throws BufferUnderflowException {
        return buf.order(ByteOrder.LITTLE_ENDIAN).getShort() & 0xFFFF;
    }

    public static int readUint16(byte[] bytes, int offset) throws ArrayIndexOutOfBoundsException {
        checkArgument(offset >= 0 && offset <= bytes.length - 2, "offset out of range: " + offset);
        return readUint16(ByteBuffer.wrap(bytes, offset, bytes.length - offset));
    }

    public static int readUint16BE(ByteBuffer buf) throws BufferUnderflowException {
        return buf.order(ByteOrder.BIG_ENDIAN).getShort() & 0xFFFF;
    }

    public static int readUint16BE(byte[] bytes, int offset) throws ArrayIndexOutOfBoundsException {
        checkArgument(offset >= 0 && offset <= bytes.length - 2, "offset out of range: " + offset);
        return readUint16BE(ByteBuffer.wrap(bytes, offset, bytes.length - offset));
    }

    public static long readUint32(ByteBuffer buf) throws BufferUnderflowException {
        return buf.order(ByteOrder.LITTLE_ENDIAN).getInt() & 0xFFFFFFFFL;
    }

    public static int readInt32(ByteBuffer buf) throws BufferUnderflowException {
        return buf.order(ByteOrder.LITTLE_ENDIAN).getInt();
    }

    public static long readUint32(byte[] bytes, int offset) throws ArrayIndexOutOfBoundsException {
        checkArgument(offset >= 0 && offset <= bytes.length - 4, "offset out of range: " + offset);
        return readUint32(ByteBuffer.wrap(bytes, offset, bytes.length - offset));
    }

    public static long readUint32BE(ByteBuffer buf) throws BufferUnderflowException {
        return buf.order(ByteOrder.BIG_ENDIAN).getInt() & 0xFFFFFFFFL;
    }

    public static long readUint32BE(byte[] bytes, int offset) throws ArrayIndexOutOfBoundsException {
        checkArgument(offset >= 0 && offset <= bytes.length - 4, "offset out of range: " + offset);
        return readUint32BE(ByteBuffer.wrap(bytes, offset, bytes.length - offset));
    }

    public static long readInt64(ByteBuffer buf) throws BufferUnderflowException {
        return buf.order(ByteOrder.LITTLE_ENDIAN).getLong();
    }

    public static long readInt64(byte[] bytes, int offset) throws ArrayIndexOutOfBoundsException {
        checkArgument(offset >= 0 && offset <= bytes.length - 8, "offset out of range: " + offset);
        return readInt64(ByteBuffer.wrap(bytes, offset, bytes.length - offset));
    }

    public static int readUint16(InputStream is) {
        byte[] buf = new byte[2];
        try {
            is.read(buf);
            return readUint16(ByteBuffer.wrap(buf));
        } catch (IOException x) {
            throw new RuntimeException(x);
        }
    }

    public static long readUint32(InputStream is) {
        byte[] buf = new byte[4];
        try {
            is.read(buf);
            return readUint32(ByteBuffer.wrap(buf));
        } catch (IOException x) {
            throw new RuntimeException(x);
        }
    }

    public static byte[] reverseBytes(byte[] bytes) {
        byte[] buf = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++)
            buf[i] = bytes[bytes.length - 1 - i];
        return buf;
    }

    public static BigInteger decodeMPI(byte[] mpi, boolean hasLength) {
        byte[] buf;
        if (hasLength) {
            int length = (int) readUint32BE(mpi, 0);
            buf = new byte[length];
            System.arraycopy(mpi, 4, buf, 0, length);
        } else {
            buf = mpi;
        }
        if (buf.length == 0) {
            return BigInteger.ZERO;
        }
        boolean isNegative = (buf[0] & 0x80) == 0x80;
        if (isNegative) {
            buf[0] &= 0x7f;
        }
        BigInteger result = new BigInteger(buf);
        return isNegative ? result.negate() : result;
    }

    public static byte[] encodeMPI(BigInteger value, boolean includeLength) {
        if (value.equals(BigInteger.ZERO)) {
            if (!includeLength) {
                return new byte[]{};
            } else {
                return new byte[]{0x00, 0x00, 0x00, 0x00};
            }
        }
        boolean isNegative = value.signum() < 0;
        if (isNegative) {
            value = value.negate();
        }
        byte[] array = value.toByteArray();
        int length = array.length;
        if ((array[0] & 0x80) == 0x80) {
            length++;
        }
        if (includeLength) {
            byte[] result = new byte[length + 4];
            System.arraycopy(array, 0, result, length - array.length + 3, array.length);
            writeInt32BE(length, result, 0);
            if (isNegative) {
                result[4] |= 0x80;
            }
            return result;
        } else {
            byte[] result;
            if (length != array.length) {
                result = new byte[length];
                System.arraycopy(array, 0, result, 1, array.length);
            } else {
                result = array;
            }
            if (isNegative) {
                result[0] |= 0x80;
            }
            return result;
        }
    }

    public static BigInteger decodeCompactBits(long compact) {
        int size = ((int) (compact >> 24)) & 0xFF;
        byte[] bytes = new byte[4 + size];
        bytes[3] = (byte) size;
        if (size >= 1) bytes[4] = (byte) ((compact >> 16) & 0xFF);
        if (size >= 2) bytes[5] = (byte) ((compact >> 8) & 0xFF);
        if (size >= 3) bytes[6] = (byte) (compact & 0xFF);
        return decodeMPI(bytes, true);
    }

    public static long encodeCompactBits(BigInteger value) {
        long result;
        int size = value.toByteArray().length;
        if (size <= 3)
            result = value.longValue() << 8 * (3 - size);
        else
            result = value.shiftRight(8 * (size - 3)).longValue();
        if ((result & 0x00800000L) != 0) {
            result >>= 8;
            size++;
        }
        result |= (long) size << 24;
        result |= value.signum() == -1 ? 0x00800000 : 0;
        return result;
    }

    public static boolean checkBitLE(byte[] data, int index) {
        return (data[index >>> 3] & bitMask[7 & index]) != 0;
    }

    public static void setBitLE(byte[] data, int index) {
        data[index >>> 3] |= bitMask[7 & index];
    }

    public static Comparator<byte[]> arrayUnsignedComparator() {
        return ARRAY_UNSIGNED_COMPARATOR;
    }

    private static final Comparator<byte[]> ARRAY_UNSIGNED_COMPARATOR = new Comparator<byte[]>() {
        @Override
        public int compare(byte[] a, byte[] b) {
            int minLength = Math.min(a.length, b.length);
            for (int i = 0; i < minLength; i++) {
                int result = compareUnsigned(a[i], b[i]);
                if (result != 0) {
                    return result;
                }
            }
            return a.length - b.length;
        }
    };

    private static int compareUnsigned(byte a, byte b) {
        return (a & 0xFF) - (b & 0xFF);
    }

    public static byte[] concat(byte[] b1, byte[] b2) {
        byte[] result = new byte[b1.length + b2.length];
        System.arraycopy(b1, 0, result, 0, b1.length);
        System.arraycopy(b2, 0, result, b1.length, b2.length);
        return result;
    }

    // Custom Supplier interface to be compatible with Java 1.7
    public interface Supplier<T> {
        T get();
    }

    private static void checkArgument(boolean expression, String message) {
        if (!expression) {
            throw new IllegalArgumentException(message);
        }
    }

    private static void checkArgument(boolean expression, Supplier<String> messageSupplier) {
        if (!expression) {
            throw new IllegalArgumentException(messageSupplier.get());
        }
    }
}
