/**
 * aesgcmmodule.cpp -- Python wrappers around Crypto++'s AES-GCM
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#if (PY_VERSION_HEX < 0x02050000)
typedef int Py_ssize_t;
#endif

#include "aesgcmmodule.hpp"

/* from Crypto++ */
#ifdef DISABLE_EMBEDDED_CRYPTOPP
#include <cryptopp/gcm.h>
#include <cryptopp/aes.h>
#else
#include <src-cryptopp/gcm.h>
#include <src-cryptopp/aes.h>
#endif

static const char*const aesgcm___doc__ = "_aes gcm mode cipher";

static PyObject *aesgcm_error;

typedef struct {
    PyObject_HEAD

    /* internal */
    CryptoPP::GCM<CryptoPP::AES>::Encryption * e;
    CryptoPP::GCM<CryptoPP::AES>::Decryption * d;
    Py_ssize_t ivsize;
    const byte *iv;
} AESGCM;

PyDoc_STRVAR(AESGCM__doc__,
"AES GCM Doc");

static PyObject *
AESGCM_decrypt_verify(AESGCM* self, PyObject* args) {
    const char *msg, *tag;
    Py_ssize_t msgsize, tagsize;
    PyArg_ParseTuple(args, "t#t#", &msg, &msgsize, &tag, &tagsize);

    assert (msgsize >= 0);
    assert (tagsize >= 0);

    PyStringObject* result = reinterpret_cast<PyStringObject*>(PyString_FromStringAndSize(NULL, msgsize));
    if (!result)
        return NULL;

    //virtual bool DecryptAndVerify(byte *message, const byte *mac, size_t macLength, const byte *iv, int ivLength, const byte *header, size_t headerLength, const byte *ciphertext, size_t ciphertextLength);
    self->d->DecryptAndVerify(reinterpret_cast<byte*>(PyString_AS_STRING(result)), reinterpret_cast<const byte*>(tag), tagsize, self->iv, self->ivsize, NULL, 0, reinterpret_cast<const byte*>(msg), msgsize);
    return reinterpret_cast<PyObject*>(result);

}

PyDoc_STRVAR(AESGCM_process__doc__,
"Encrypt or decrypt the next bytes, returning the result.");

static PyMethodDef AESGCM_methods[] = {
    {"decrypt_and_verify", reinterpret_cast<PyCFunction>(AESGCM_decrypt_verify), METH_VARARGS , AESGCM_process__doc__},
    {NULL},
};

static PyObject *
AESGCM_new(PyTypeObject* type, PyObject *args, PyObject *kwdict) {
    AESGCM* self = reinterpret_cast<AESGCM*>(type->tp_alloc(type, 0));
    if (!self)
        return NULL;
    self->d = NULL;
    return reinterpret_cast<PyObject*>(self);
}

static void
AESGCM_dealloc(PyObject* self) {
    if (reinterpret_cast<AESGCM*>(self)->e)
        delete reinterpret_cast<AESGCM*>(self)->e;
    self->ob_type->tp_free(self);
}

static int
AESGCM_init(PyObject* self, PyObject *args, PyObject *kwdict) {
    static const char *kwlist[] = { "key", "iv", NULL };
    const char *key = NULL;
    Py_ssize_t keysize = 0;
    const char *iv = NULL;
    const char defaultiv[CryptoPP::AES::BLOCKSIZE] = {0};
    Py_ssize_t ivsize = 0;
    if (!PyArg_ParseTupleAndKeywords(args, kwdict, "t#|t#:AESGCM.__init__", const_cast<char**>(kwlist), &key, &keysize, &iv, &ivsize))
        return -1;
    assert (keysize >= 0);
    assert (ivsize >= 0);

    if (!iv)
        iv = defaultiv;
    else if (ivsize != 16) {
        //PyErr_Format(aes_error, "Precondition violation: if an IV is passed, it must be exactly 16 bytes, not %d", ivsize);
        //return -1;
    }
    try {
        //reinterpret_cast<AESGCM*>(self)->d = new CryptoPP::GCM<CryptoPP::AES>::Decryption(reinterpret_cast<const byte*>(key), keysize, reinterpret_cast<const byte*>(iv));
        reinterpret_cast<AESGCM*>(self)->d = new CryptoPP::GCM<CryptoPP::AES>::Decryption();
	reinterpret_cast<AESGCM*>(self)->d->SetKeyWithIV(reinterpret_cast<const byte*>(key), keysize, reinterpret_cast<const byte*>(iv), ivsize);
	reinterpret_cast<AESGCM*>(self)->iv = reinterpret_cast<const byte*>(iv);
 	reinterpret_cast<AESGCM*>(self)->ivsize = ivsize;
    } catch (CryptoPP::InvalidKeyLength le) {
        PyErr_Format(aesgcm_error, "Precondition violation: you are required to pass a valid key size.  Crypto++ gave this exception: %s", le.what());
        return -1;
    }
    if (!reinterpret_cast<AESGCM*>(self)->d) {
        PyErr_NoMemory();
        return -1;
    }
    return 0;
}

static PyTypeObject AESGCM_type = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "_aesgcm.AESGCM", /*tp_name*/
    sizeof(AESGCM),             /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    AESGCM_dealloc, /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    0,                         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    AESGCM__doc__,           /* tp_doc */
    0,		               /* tp_traverse */
    0,		               /* tp_clear */
    0,		               /* tp_richcompare */
    0,		               /* tp_weaklistoffset */
    0,		               /* tp_iter */
    0,		               /* tp_iternext */
    AESGCM_methods,      /* tp_methods */
    0,                         /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    AESGCM_init,               /* tp_init */
    0,                         /* tp_alloc */
    AESGCM_new,                /* tp_new */
};

void
init_aesgcm(PyObject*const module) {
    if (PyType_Ready(&AESGCM_type) < 0)
        return;
    Py_INCREF(&AESGCM_type);
    PyModule_AddObject(module, "aesgcm_AESGCM", (PyObject *)&AESGCM_type);

    aesgcm_error = PyErr_NewException(const_cast<char*>("_aesgcm.Error"), NULL, NULL);
    PyModule_AddObject(module, "aesgcm_Error", aesgcm_error);

    PyModule_AddStringConstant(module, "aesgcm___doc__", const_cast<char*>(aesgcm___doc__));
}


