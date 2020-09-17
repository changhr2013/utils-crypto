package com.changhr.utils.crypto.utils;

/**
 * @author changhr
 * @create 2020-09-17 10:54
 */
public class PaddingUtil {

    private PaddingUtil() {
    }

    public static byte[] formatWithZeroPadding(byte[] data, final int blockSize) {
        final int length = data.length;
        final int remainLength = length % blockSize;

        if (remainLength > 0) {
            byte[] inputData = new byte[length + blockSize - remainLength];
            System.arraycopy(data, 0, inputData, 0, length);
            return inputData;
        }
        return data;
    }

    public static byte[] removeZeroPadding(byte[] data, final int blockSize) {
        final int length = data.length;
        final int remainLength = length % blockSize;
        if (remainLength == 0) {
            // 解码后的数据正好是块大小的整数倍，说明可能存在补 0 的情况，去掉末尾所有的 0
            int i = length - 1;
            while (i >= 0 && 0 == data[i]) {
                i--;
            }
            byte[] outputData = new byte[i + 1];
            System.arraycopy(data, 0, outputData, 0, outputData.length);
            return outputData;
        }
        return data;
    }
}
