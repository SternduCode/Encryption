package com.sterndu.encryption

import java.nio.ByteBuffer
import java.nio.ByteOrder

const val LONG_SIZE = 8
const val INT_SIZE = 4
const val SHORT_SIZE = 2
const val BYTE_SIZE = 1

const val DOUBLE_SIZE = 8
const val FLOAT_SIZE = 4

val ByteArray.packingSizeWithLength: Int get() = INT_SIZE + BYTE_SIZE * size
val ByteArray.packingSize: Int get() = BYTE_SIZE * size

val ShortArray.packingSizeWithLength: Int get() = INT_SIZE + SHORT_SIZE * size
val ShortArray.packingSize: Int get() = SHORT_SIZE * size

val IntArray.packingSizeWithLength: Int get() = INT_SIZE + INT_SIZE * size
val IntArray.packingSize: Int get() = INT_SIZE * size

val LongArray.packingSizeWithLength: Int get() = INT_SIZE + LONG_SIZE * size
val LongArray.packingSize: Int get() = LONG_SIZE * size

val FloatArray.packingSizeWithLength: Int get() = INT_SIZE + FLOAT_SIZE * size
val FloatArray.packingSize: Int get() = FLOAT_SIZE * size

val DoubleArray.packingSizeWithLength: Int get() = INT_SIZE + DOUBLE_SIZE * size
val DoubleArray.packingSize: Int get() = DOUBLE_SIZE * size

fun allocateByteBuffer(length: Int): ByteBuffer = ByteBuffer.allocate(length).order(ByteOrder.BIG_ENDIAN)

fun ByteBuffer.putByteArrayWithLength(array: ByteArray): ByteBuffer = putInt(array.size).put(array)

fun ByteBuffer.getByteArrayWithLength(): ByteArray {
    val length = int
    val array = ByteArray(length)
    get(array)
    return array
}

fun ByteBuffer.putShortArrayWithLength(array: ShortArray): ByteBuffer {
    putInt(array.size)
    for (s in array) putShort(s)
    return this
}

fun ByteBuffer.putShortArray(array: ShortArray): ByteBuffer {
    for (s in array) putShort(s)
    return this
}