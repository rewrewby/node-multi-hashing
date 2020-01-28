#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include <nan.h>

extern "C" {
    #include "bcrypt.h"
    #include "blake.h"
    #include "c11.h"
    #include "cryptonight.h"
    #include "cryptonight_fast.h"
    #include "fresh.h"
    #include "fugue.h"
    #include "groestl.h"
    #include "hefty1.h"
    #include "keccak.h"
    #include "lbry.h"
    #include "nist5.h"
    #include "quark.h"
    #include "qubit.h"
    #include "scryptjane.h"
    #include "scryptn.h"
    #include "sha1.h"
    #include "sha256d.h"
    #include "shavite3.h"
    #include "skein.h"
    #include "x11.h"
    #include "x13.h"
    #include "x15.h"
    #include "x16rt.h"
    #include "neoscrypt.h"
}

#include "boolberry.h"

using namespace node;
using namespace v8;

#if NODE_MAJOR_VERSION >= 4

#define DECLARE_INIT(x) \
    void x(Local<Object> exports)

#define DECLARE_FUNC(x) \
    void x(const FunctionCallbackInfo<Value>& args)

#define DECLARE_SCOPE \
    v8::Isolate* isolate = args.GetIsolate();

#define SET_BUFFER_RETURN(x, len) \
    args.GetReturnValue().Set(Buffer::Copy(isolate, x, len).ToLocalChecked());

#define SET_BOOLEAN_RETURN(x) \
    args.GetReturnValue().Set(Boolean::New(isolate, x));

#define RETURN_EXCEPT(msg) \
    do { \
        isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, msg))); \
        return; \
    } while (0)

#else

#define DECLARE_INIT(x) \
    void x(Handle<Object> exports)

#define DECLARE_FUNC(x) \
    Handle<Value> x(const Arguments& args)

#define DECLARE_SCOPE \
    HandleScope scope

#define SET_BUFFER_RETURN(x, len) \
    do { \
        Buffer* buff = Buffer::New(x, len); \
        return scope.Close(buff->handle_); \
    } while (0)

#define SET_BOOLEAN_RETURN(x) \
    return scope.Close(Boolean::New(x));

#define RETURN_EXCEPT(msg) \
    return ThrowException(Exception::Error(String::New(msg)))

#endif // NODE_MAJOR_VERSION

#define DECLARE_CALLBACK(name, hash, output_len) \
    DECLARE_FUNC(name) { \
    DECLARE_SCOPE; \
 \
    if (args.Length() < 1) \
        RETURN_EXCEPT("You must provide one argument."); \
 \
    Local<Object> target = Nan::To<Object>(args[0]).ToLocalChecked(); \
 \
    if(!Buffer::HasInstance(target)) \
        RETURN_EXCEPT("Argument should be a buffer object."); \
 \
    char * input = Buffer::Data(target); \
    char output[32]; \
 \
    uint32_t input_len = Buffer::Length(target); \
 \
    hash(input, output, input_len); \
 \
    SET_BUFFER_RETURN(output, output_len); \
}

 DECLARE_CALLBACK(bcrypt, bcrypt_hash, 32);
 DECLARE_CALLBACK(blake, blake_hash, 32);
 DECLARE_CALLBACK(c11, c11_hash, 32);
 DECLARE_CALLBACK(fresh, fresh_hash, 32);
 DECLARE_CALLBACK(fugue, fugue_hash, 32);
 DECLARE_CALLBACK(groestl, groestl_hash, 32);
 DECLARE_CALLBACK(groestlmyriad, groestlmyriad_hash, 32);
 DECLARE_CALLBACK(hefty1, hefty1_hash, 32);
 DECLARE_CALLBACK(keccak, keccak_hash, 32);
 DECLARE_CALLBACK(lbry, lbry_hash, 32);
 DECLARE_CALLBACK(nist5, nist5_hash, 32);
 DECLARE_CALLBACK(quark, quark_hash, 32);
 DECLARE_CALLBACK(qubit, qubit_hash, 32);
 DECLARE_CALLBACK(sha1, sha1_hash, 32);
 DECLARE_CALLBACK(sha256d, sha256d_hash, 32);
 DECLARE_CALLBACK(shavite3, shavite3_hash, 32);
 DECLARE_CALLBACK(skein, skein_hash, 32);
 DECLARE_CALLBACK(x11, x11_hash, 32);
 DECLARE_CALLBACK(x13, x13_hash, 32);
 DECLARE_CALLBACK(x16rt, x16rt_hash, 32);


void x16rt(const FunctionCallbackInfo<Value>& args) {
	DECLARE_SCOPE;

    if (args.Length() < 1)
        RETURN_EXCEPT("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(args[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        RETURN_EXCEPT("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    uint32_t input_len = Buffer::Length(target);

    x16rt_hash(input, output, input_len);

    SET_BUFFER_RETURN(output, 32);
}

void scrypt(const FunctionCallbackInfo<Value>& args) {
   DECLARE_SCOPE;

   if (args.Length() < 3)
       RETURN_EXCEPT("You must provide buffer to hash, N value, and R value");

   Local<Object> target = Nan::To<Object>(args[0]).ToLocalChecked();

   if(!Buffer::HasInstance(target))
       RETURN_EXCEPT("Argument should be a buffer object.");

   unsigned int nValue = args[1]->Uint32Value(Nan::GetCurrentContext()).FromJust();
   unsigned int rValue = args[2]->Uint32Value(Nan::GetCurrentContext()).FromJust();

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   scrypt_N_R_1_256(input, output, nValue, rValue, input_len);

   SET_BUFFER_RETURN(output, 32);
}

void neoscrypt(const FunctionCallbackInfo<Value>& args) {
   DECLARE_SCOPE;

   if (args.Length() < 2)
       RETURN_EXCEPT("You must provide two arguments");

   Local<Object> target = Nan::To<Object>(args[0]).ToLocalChecked();

   if(!Buffer::HasInstance(target))
       RETURN_EXCEPT("Argument should be a buffer object.");

   // unsigned int nValue = args[1]->Uint32Value();
   // unsigned int rValue = args[2]->Uint32Value();

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   neoscrypt(input, output, 0);

   SET_BUFFER_RETURN(output, 32);
}

void scryptn(const FunctionCallbackInfo<Value>& args) {
   DECLARE_SCOPE;

   if (args.Length() < 2)
       RETURN_EXCEPT("You must provide buffer to hash and N factor.");

   Local<Object> target = Nan::To<Object>(args[0]).ToLocalChecked();

   if(!Buffer::HasInstance(target))
       RETURN_EXCEPT("Argument should be a buffer object.");

   unsigned int nFactor = args[1]->Uint32Value(Nan::GetCurrentContext()).FromJust();

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   //unsigned int N = 1 << (getNfactor(input) + 1);
   unsigned int N = 1 << nFactor;

   scrypt_N_R_1_256(input, output, N, 1, input_len); //hardcode for now to R=1 for now

   SET_BUFFER_RETURN(output, 32);
}

void scryptjane(const FunctionCallbackInfo<Value>& args) {
    DECLARE_SCOPE;

    if (args.Length() < 5)
        RETURN_EXCEPT("You must provide two argument: buffer, timestamp as number, and nChainStarTime as number, nMin, and nMax");

    Local<Object> target = Nan::To<Object>(args[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        RETURN_EXCEPT("First should be a buffer object.");

	int timestamp = args[1]->Int32Value(Nan::GetCurrentContext()).FromJust();
	int nChainStartTime = args[2]->Int32Value(Nan::GetCurrentContext()).FromJust();
	int nMin = args[3]->Int32Value(Nan::GetCurrentContext()).FromJust();
	int nMax = args[4]->Int32Value(Nan::GetCurrentContext()).FromJust();

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    scryptjane_hash(input, input_len, (uint32_t *)output, GetNfactorJane(timestamp, nChainStartTime, nMin, nMax));

    SET_BUFFER_RETURN(output, 32);
}

void cryptonight(const FunctionCallbackInfo<Value>& args) {
    DECLARE_SCOPE;

    bool fast = false;
    uint32_t cn_variant = 0;
    uint64_t height = 0;

    if (args.Length() < 1)
        RETURN_EXCEPT("You must provide one argument.");

    if (args.Length() >= 2) {
		if (args[1]->IsBoolean())
			fast = args[1]->BooleanValue(Nan::GetCurrentContext()).FromJust();
		else if (args[1]->IsUint32())
			cn_variant = args[1]->Uint32Value(Nan::GetCurrentContext()).FromJust();
        else
            RETURN_EXCEPT("Argument 2 should be a boolean or uint32_t");
    }

    if ((cn_variant == 4) && (args.Length() < 3)) {
        RETURN_EXCEPT("You must provide Argument 3 (block height) for Cryptonight variant 4");
    }

    if (args.Length() >= 3) {
        if(args[2]->IsUint32())
			height = args[2]->Uint32Value(Nan::GetCurrentContext()).FromJust();
        else
            RETURN_EXCEPT("Argument 3 should be uint32_t");
    }

    Local<Object> target = Nan::To<Object>(args[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        RETURN_EXCEPT("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    if(fast)
        cryptonight_fast_hash(input, output, input_len);
    else {
        if ((cn_variant == 1) && input_len < 43)
            RETURN_EXCEPT("Argument must be 43 bytes for monero variant 1");
        cryptonight_hash(input, output, input_len, cn_variant, height);
    }
    SET_BUFFER_RETURN(output, 32);
}
void cryptonightfast(const FunctionCallbackInfo<Value>& args) {
    DECLARE_SCOPE;

    bool fast = false;
    uint32_t cn_variant = 0;

    if (args.Length() < 1)
        RETURN_EXCEPT("You must provide one argument.");

    if (args.Length() >= 2) {
		if (args[1]->IsBoolean())
			fast = args[1]->BooleanValue(Nan::GetCurrentContext()).FromJust();
		else if (args[1]->IsUint32())
			cn_variant = args[1]->Uint32Value(Nan::GetCurrentContext()).FromJust();
        else
            RETURN_EXCEPT("Argument 2 should be a boolean or uint32_t");
    }

    Local<Object> target = Nan::To<Object>(args[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        RETURN_EXCEPT("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    if(fast)
        cryptonightfast_fast_hash(input, output, input_len);
    else {
        if (cn_variant > 0 && input_len < 43)
            RETURN_EXCEPT("Argument must be 43 bytes for monero variant 1+");
        cryptonightfast_hash(input, output, input_len, cn_variant);
    }
    SET_BUFFER_RETURN(output, 32);
}
void boolberry(const FunctionCallbackInfo<Value>& args) {
    DECLARE_SCOPE;

    if (args.Length() < 2)
        RETURN_EXCEPT("You must provide two arguments.");

	Local<Object> target = Nan::To<Object>(args[0]).ToLocalChecked();
	Local<Object> target_spad = Nan::To<Object>(args[1]).ToLocalChecked();
    uint32_t height = 1;

    if(!Buffer::HasInstance(target))
        RETURN_EXCEPT("Argument 1 should be a buffer object.");

    if(!Buffer::HasInstance(target_spad))
        RETURN_EXCEPT("Argument 2 should be a buffer object.");

    if(args.Length() >= 3) {
        if(args[2]->IsUint32())
			height = args[2]->Uint32Value(Nan::GetCurrentContext()).FromJust();
        else
            RETURN_EXCEPT("Argument 3 should be an unsigned integer.");
    }

    char * input = Buffer::Data(target);
    char * scratchpad = Buffer::Data(target_spad);
    char output[32];

    uint32_t input_len = Buffer::Length(target);
    uint64_t spad_len = Buffer::Length(target_spad);

    boolberry_hash(input, input_len, scratchpad, spad_len, output, height);

    SET_BUFFER_RETURN(output, 32);
}

void Init(Local<Object> exports, Local<Context> context) {
	Isolate* isolate = context->GetIsolate();
	exports->Set(context, String::NewFromUtf8(isolate, "bcrypt", NewStringType::kNormal) .ToLocalChecked(),
		FunctionTemplate::New(isolate, bcrypt)->GetFunction(context).ToLocalChecked()).FromJust();
	exports->Set(context, String::NewFromUtf8(isolate, "blake", NewStringType::kNormal).ToLocalChecked(),
		FunctionTemplate::New(isolate, blake)->GetFunction(context).ToLocalChecked()).FromJust();
	exports->Set(context, String::NewFromUtf8(isolate, "boolberry", NewStringType::kNormal).ToLocalChecked(),
		FunctionTemplate::New(isolate, boolberry)->GetFunction(context).ToLocalChecked()).FromJust();
	exports->Set(context, String::NewFromUtf8(isolate, "c11", NewStringType::kNormal).ToLocalChecked(),
		FunctionTemplate::New(isolate, c11)->GetFunction(context).ToLocalChecked()).FromJust();
	exports->Set(context, String::NewFromUtf8(isolate, "cryptonight", NewStringType::kNormal).ToLocalChecked(),
		FunctionTemplate::New(isolate, cryptonight)->GetFunction(context).ToLocalChecked()).FromJust();
	exports->Set(context, String::NewFromUtf8(isolate, "cryptonightfast", NewStringType::kNormal).ToLocalChecked(),
		FunctionTemplate::New(isolate, cryptonightfast)->GetFunction(context).ToLocalChecked()).FromJust();
	exports->Set(context, String::NewFromUtf8(isolate, "fresh", NewStringType::kNormal).ToLocalChecked(),
		FunctionTemplate::New(isolate, fresh)->GetFunction(context).ToLocalChecked()).FromJust();
	exports->Set(context, String::NewFromUtf8(isolate, "fugue", NewStringType::kNormal).ToLocalChecked(),
		FunctionTemplate::New(isolate, fugue)->GetFunction(context).ToLocalChecked()).FromJust();
	exports->Set(context, String::NewFromUtf8(isolate, "groestl", NewStringType::kNormal).ToLocalChecked(),
		FunctionTemplate::New(isolate, groestl)->GetFunction(context).ToLocalChecked()).FromJust();
	exports->Set(context, String::NewFromUtf8(isolate, "groestlmyriad", NewStringType::kNormal).ToLocalChecked(),
		FunctionTemplate::New(isolate, groestlmyriad)->GetFunction(context).ToLocalChecked()).FromJust();
	exports->Set(context, String::NewFromUtf8(isolate, "hefty1", NewStringType::kNormal).ToLocalChecked(),
		FunctionTemplate::New(isolate, hefty1)->GetFunction(context).ToLocalChecked()).FromJust();
	exports->Set(context, String::NewFromUtf8(isolate, "keccak", NewStringType::kNormal).ToLocalChecked(),
		FunctionTemplate::New(isolate, keccak)->GetFunction(context).ToLocalChecked()).FromJust();
	exports->Set(context, String::NewFromUtf8(isolate, "lbry", NewStringType::kNormal).ToLocalChecked(),
		FunctionTemplate::New(isolate, lbry)->GetFunction(context).ToLocalChecked()).FromJust();
	exports->Set(context, String::NewFromUtf8(isolate, "nist5", NewStringType::kNormal).ToLocalChecked(),
		FunctionTemplate::New(isolate, nist5)->GetFunction(context).ToLocalChecked()).FromJust();
	exports->Set(context, String::NewFromUtf8(isolate, "quark", NewStringType::kNormal).ToLocalChecked(),
		FunctionTemplate::New(isolate, quark)->GetFunction(context).ToLocalChecked()).FromJust();
	exports->Set(context, String::NewFromUtf8(isolate, "qubit", NewStringType::kNormal).ToLocalChecked(),
		FunctionTemplate::New(isolate, qubit)->GetFunction(context).ToLocalChecked()).FromJust();
	exports->Set(context, String::NewFromUtf8(isolate, "scrypt", NewStringType::kNormal).ToLocalChecked(),
		FunctionTemplate::New(isolate, scrypt)->GetFunction(context).ToLocalChecked()).FromJust();
	exports->Set(context, String::NewFromUtf8(isolate, "scryptjane", NewStringType::kNormal).ToLocalChecked(),
		FunctionTemplate::New(isolate, scryptjane)->GetFunction(context).ToLocalChecked()).FromJust();
	exports->Set(context, String::NewFromUtf8(isolate, "scryptn", NewStringType::kNormal).ToLocalChecked(),
		FunctionTemplate::New(isolate, scryptn)->GetFunction(context).ToLocalChecked()).FromJust();
	exports->Set(context, String::NewFromUtf8(isolate, "neoscrypt", NewStringType::kNormal).ToLocalChecked(),
		FunctionTemplate::New(isolate, neoscrypt)->GetFunction(context).ToLocalChecked()).FromJust();
	exports->Set(context, String::NewFromUtf8(isolate, "sha1", NewStringType::kNormal).ToLocalChecked(),
		FunctionTemplate::New(isolate, sha1)->GetFunction(context).ToLocalChecked()).FromJust();
	exports->Set(context, String::NewFromUtf8(isolate, "sha256d", NewStringType::kNormal).ToLocalChecked(),
		FunctionTemplate::New(isolate, sha256d)->GetFunction(context).ToLocalChecked()).FromJust();
	exports->Set(context, String::NewFromUtf8(isolate, "skein", NewStringType::kNormal).ToLocalChecked(),
		FunctionTemplate::New(isolate, skein)->GetFunction(context).ToLocalChecked()).FromJust();
	exports->Set(context, String::NewFromUtf8(isolate, "x11", NewStringType::kNormal).ToLocalChecked(),
		FunctionTemplate::New(isolate, x11)->GetFunction(context).ToLocalChecked()).FromJust();
	exports->Set(context, String::NewFromUtf8(isolate, "x13", NewStringType::kNormal).ToLocalChecked(),
		FunctionTemplate::New(isolate, x13)->GetFunction(context).ToLocalChecked()).FromJust();
	exports->Set(context, String::NewFromUtf8(isolate, "x15", NewStringType::kNormal).ToLocalChecked(),
		FunctionTemplate::New(isolate, x15)->GetFunction(context).ToLocalChecked()).FromJust();
	exports->Set(context, String::NewFromUtf8(isolate, "x16rt", NewStringType::kNormal).ToLocalChecked(),
		FunctionTemplate::New(isolate, x16rt)->GetFunction(context).ToLocalChecked()).FromJust();
}

//NODE_MODULE(multihashing, init)
NODE_MODULE_INIT(/* exports, module, context */) {
	Init(exports, context);
}
