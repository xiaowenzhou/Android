### 1.Binder概述

分析mediaPlayer过程

1.main_mediaserver.cpp

```c++
int main(int argc __unused, char **argv __unused)
{
    signal(SIGPIPE, SIG_IGN);

    //获得ProcessState实例
    sp<ProcessState> proc(ProcessState::self());
    //获取ServiceManager对象
    sp<IServiceManager> sm(defaultServiceManager());
    ALOGI("ServiceManager: %p", sm.get());
    AIcu_initializeIcuOrDie();
    //注册多媒体服务
    MediaPlayerService::instantiate();
    ResourceManagerService::instantiate();
    configureRpcThreadpool(4, true /* callerWillJoin */);
    registerExtensions();
    //启动binder线程池
    ProcessState::self()->startThreadPool();
    //当前线程加入线程池
    IPCThreadState::self()->joinThreadPool();
}

```

2.ProcessState.cpp

```c++
//使用单例模式获得ProcessState对象
//获得ProcessState对象: 这也是单例模式，从而保证每一个进程只有一个ProcessState对象。其中gProcess和gProcessMutex是保存在Static.cpp类的全局变量。
sp<ProcessState> ProcessState::self()
{
    Mutex::Autolock _l(gProcessMutex);
    if (gProcess != nullptr) {
        return gProcess;
    }
    gProcess = new ProcessState(kDefaultDriver);
    return gProcess;
}
```

```
ProcessState::ProcessState(const char *driver)
    : mDriverName(String8(driver))//设置binder驱动名字
    , mDriverFD(open_driver(driver))//打开binder驱动
    , mVMStart(MAP_FAILED)
    , mThreadCountLock(PTHREAD_MUTEX_INITIALIZER)
    , mThreadCountDecrement(PTHREAD_COND_INITIALIZER)
    , mExecutingThreadsCount(0)
    , mMaxThreads(DEFAULT_MAX_BINDER_THREADS)
    , mStarvationStartTimeMs(0)
    , mManagesContexts(false)
    , mBinderContextCheckFunc(nullptr)
    , mBinderContextUserData(nullptr)
    , mThreadPoolStarted(false)
    , mThreadPoolSeq(1)
    , mCallRestriction(CallRestriction::NONE)
{
    if (mDriverFD >= 0) {
        // mmap the binder, providing a chunk of virtual address space to receive transactions.
        //采用内存映射函数mmap，给binder分配一块虚拟地址
        mVMStart = mmap(nullptr, BINDER_VM_SIZE, PROT_READ, MAP_PRIVATE | MAP_NORESERVE, mDriverFD, 0);
        if (mVMStart == MAP_FAILED) {
            // *sigh*
            //没有足够的空间可以分配，关闭驱动
            ALOGE("Using %s failed: unable to mmap transaction memory.\n", mDriverName.c_str());
            close(mDriverFD);
            mDriverFD = -1;
            mDriverName.clear();
        }
    }

    LOG_ALWAYS_FATAL_IF(mDriverFD < 0, "Binder driver could not be opened.  Terminating.");
}

#define BINDER_VM_SIZE ((1 * 1024 * 1024) - sysconf(_SC_PAGE_SIZE) * 2)，binder分配的默认内存大小为1M—8K sysconf(_SC_PAGE_SIZE)获取内存页的大小
#define DEFAULT_MAX_BINDER_THREADS 15 binder默认最大的并发访问线程数为16  0-15
```

```c++
#ifdef __ANDROID_VNDK__
const char* kDefaultDriver = "/dev/vndbinder";
#else
const char* kDefaultDriver = "/dev/binder";
#endif

static int open_driver(const char *driver)
{
    //打开binder设备 10.0binder设备有两个/dev/vndbinder和/dev/binder 谷歌区分vendor下的system下的可执行文件
    int fd = open(driver, O_RDWR | O_CLOEXEC);
    if (fd >= 0) {
        int vers = 0;
        status_t result = ioctl(fd, BINDER_VERSION, &vers);
        if (result == -1) {
            ALOGE("Binder ioctl to obtain version failed: %s", strerror(errno));
            close(fd);
            fd = -1;
        }
        //判断binder版本
        if (result != 0 || vers != BINDER_CURRENT_PROTOCOL_VERSION) {
          ALOGE("Binder driver protocol(%d) does not match user space protocol(%d)! ioctl() return value: %d",
                vers, BINDER_CURRENT_PROTOCOL_VERSION, result);
            close(fd);
            fd = -1;
        }
        size_t maxThreads = DEFAULT_MAX_BINDER_THREADS;
        //通过ioctl设置binder驱动能支持的最大线程数
        result = ioctl(fd, BINDER_SET_MAX_THREADS, &maxThreads);
        if (result == -1) {
            ALOGE("Binder ioctl to set max threads failed: %s", strerror(errno));
        }
    } else {
        ALOGW("Opening '%s' failed: %s\n", driver, strerror(errno));
    }
    return fd;
}

```

3.服务注册

```c++
void MediaPlayerService::instantiate() {
    defaultServiceManager()->addService(
            String16("media.player"), new MediaPlayerService());
}

注册服务MediaPlayerService：由defaultServiceManager()返回的是BpServiceManager，同时会创建ProcessState对象和BpBinder对象。 故此处等价于调用BpServiceManager->addService。其中MediaPlayerService位于libmediaplayerservice库.
```

4.IServiceManager.cpp ::BpServiceManager

```c++
virtual status_t addService(const String16& name, const sp<IBinder>& service,
                                bool allowIsolated, int dumpsysPriority) {
        Parcel data, reply;//数据包
        //写入头信息"android.os.IServiceManager"
        data.writeInterfaceToken(IServiceManager::getInterfaceDescriptor());
        data.writeString16(name);//name为"media.player"
        data.writeStrongBinder(service);//MediaPlayerService对象
        data.writeInt32(allowIsolated ? 1 : 0);allowIsolated=false
        data.writeInt32(dumpsysPriority);//没查到 大概是 dumpsys的优先级
        status_t err = remote()->transact(ADD_SERVICE_TRANSACTION, data, &reply);//remote()指向BpBinder对象
        return err == NO_ERROR ? reply.readExceptionCode() : err;
    }
```

```c++
status_t Parcel::writeStrongBinder(const sp<IBinder>& val)
{
    return flatten_binder(ProcessState::self(), val, this);
}
```

```c++
//有两个方法，根据binder 类型不同 此处选sp<IBinder>
status_t flatten_binder(const sp<ProcessState>& /*proc*/,
    const sp<IBinder>& binder, Parcel* out)
{
    flat_binder_object obj;

    if (IPCThreadState::self()->backgroundSchedulingDisabled()) {
        /* minimum priority for all nodes is nice 0 */
        obj.flags = FLAT_BINDER_FLAG_ACCEPTS_FDS;
    } else {
        /* minimum priority for all nodes is MAX_NICE(19) */
        obj.flags = 0x13 | FLAT_BINDER_FLAG_ACCEPTS_FDS;
    }

    if (binder != nullptr) {
        //可以看到这里对传入的binder做了判断，到底是BBinder还是BpBinder
        //推测是Client端过来是BpBinder,而Service端是BBinder 个人理解此处如果是BpBinder         localBinder返回肯定是空，所以 会重新获取 BpBinder *proxy = binder->remoteBinder();否则的话直接走客户端处理即BBBinder
        //主要是扁平化处理，将binder参数，转化为flat_binder_object,
        //当是BpBinder时，用handle存储handle,当是BBinder时用cookie记录binder
        BBinder *local = binder->localBinder();//本地binder非空
        if (!local) {
            BpBinder *proxy = binder->remoteBinder();
            if (proxy == nullptr) {
                ALOGE("null proxy");
            }
            const int32_t handle = proxy ? proxy->handle() : 0;
            obj.hdr.type = BINDER_TYPE_HANDLE;
            obj.binder = 0; /* Don't pass uninitialized stack data to a remote process */
            obj.handle = handle;
            obj.cookie = 0;
        } else {//进入此分支
            if (local->isRequestingSid()) {
                obj.flags |= FLAT_BINDER_FLAG_TXN_SECURITY_CTX;
            }
            obj.hdr.type = BINDER_TYPE_BINDER;
            obj.binder = reinterpret_cast<uintptr_t>(local->getWeakRefs());
            obj.cookie = reinterpret_cast<uintptr_t>(local);
        }
    } else {
        obj.hdr.type = BINDER_TYPE_BINDER;
        obj.binder = 0;
        obj.cookie = 0;
    }

    return finish_flatten_binder(binder, obj, out);
}
```

将Binder对象扁平化，转成flat_binder_object对象

- 对于Binder实体，则cookie记录Binder实体的指针；
- 对于Binder代理，则用handle记录Binder代理的句柄；

```c++
BBinder* BBinder::localBinder()
{
    return this;
}

BBinder* IBinder::localBinder()
{
    return nullptr;
}
```

所以 localBinder非空

```c++
inline static status_t finish_flatten_binder(
    const sp<IBinder>& /*binder*/, const flat_binder_object& flat, Parcel* out)
{
    return out->writeObject(flat, false);
}
```

将flat_binder_object 写入out

5.“status_t err = remote()->transact(ADD_SERVICE_TRANSACTION, data, &reply);//remote()指向BpBinder对象” 分析：

https://blog.csdn.net/lb377463323/article/details/78385845 由这篇博客分析：

```c++
gDefaultServiceManager = interface_cast<IServiceManager>(
                ProcessState::self()->getContextObject(nullptr));
//gDefaultServiceManager 会初始化BpServiceManager 继承BpInterface 再继承BpRefBase
inline  IBinder*        remote()                { return mRemote; }
//remote() 返回mRemote变量   
```

```c++
BpRefBase::BpRefBase(const sp<IBinder>& o)
    : mRemote(o.get()), mRefs(nullptr), mState(0)
{
    extendObjectLifetime(OBJECT_LIFETIME_WEAK);

    if (mRemote) {
        mRemote->incStrong(this);           // Removed on first IncStrong().
        mRefs = mRemote->createWeak(this);  // Held for our entire lifetime.
    }
}
```

一直好奇mRemote 是如何赋值的，参考的博客也没有说明

上面分析知 BpServiceManage 继承至BpRefBase 

interface_cast<IServiceManager>(
                ProcessState::self()->getContextObject(nullptr)) 即相当于 

```
 BpServiceManager(const sp<IBinder>& ProcessState::self()->getContextObject(nullptr))
        : BpInterface<IServiceManager>(ProcessState::self()->getContextObject(nullptr))
```

-》即

BpRefBase(const sp<IBinder>& o) 中的o即为ProcessState::self()->getContextObject(nullptr)

```c++
sp<IBinder> ProcessState::getStrongProxyForHandle(int32_t handle)
{
    sp<IBinder> result;

    AutoMutex _l(mLock);

    handle_entry* e = lookupHandleLocked(handle);

    if (e != nullptr) {
        // We need to create a new BpBinder if there isn't currently one, OR we
        // are unable to acquire a weak reference on this current one.  See comment
        // in getWeakProxyForHandle() for more info about this.
        IBinder* b = e->binder;
        if (b == nullptr || !e->refs->attemptIncWeak(this)) {
            if (handle == 0) {
                // Special case for context manager...
                // The context manager is the only object for which we create
                // a BpBinder proxy without already holding a reference.
                // Perform a dummy transaction to ensure the context manager
                // is registered before we create the first local reference
                // to it (which will occur when creating the BpBinder).
                // If a local reference is created for the BpBinder when the
                // context manager is not present, the driver will fail to
                // provide a reference to the context manager, but the
                // driver API does not return status.
                //
                // Note that this is not race-free if the context manager
                // dies while this code runs.
                //
                // TODO: add a driver API to wait for context manager, or
                // stop special casing handle 0 for context manager and add
                // a driver API to get a handle to the context manager with
                // proper reference counting.

                Parcel data;
                status_t status = IPCThreadState::self()->transact(
                        0, IBinder::PING_TRANSACTION, data, nullptr, 0);
                if (status == DEAD_OBJECT)
                   return nullptr;
            }

            b = BpBinder::create(handle);//获取bpBinder实例
            e->binder = b;
            if (b) e->refs = b->getWeakRefs();
            result = b;
        } else {
            // This little bit of nastyness is to allow us to add a primary
            // reference to the remote proxy when this team doesn't have one
            // but another team is sending the handle to us.
            result.force_set(b);
            e->refs->decWeak(this);
        }
    }

    return result;
}
```

至此我们知道 mRemote指向的是Binder 代理类

接下来即可以找到BpBinder中的transact方法

```c++
status_t BpBinder::transact(
    uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags)
{
    // Once a binder has died, it will never come back to life.
    if (mAlive) {
        status_t status = IPCThreadState::self()->transact(
            mHandle, code, data, reply, flags);
        if (status == DEAD_OBJECT) mAlive = 0;
        return status;
    }

    return DEAD_OBJECT;
}
```

BpBinder中调用transact()方法，还是交给IPCThreadState::self()->transact()来实现的

6.IPCThreadState::self()

```c++
IPCThreadState* IPCThreadState::self()
{
    if (gHaveTLS) {
restart:
        const pthread_key_t k = gTLS;
        IPCThreadState* st = (IPCThreadState*)pthread_getspecific(k);
        if (st) return st;
        return new IPCThreadState;//初始化IPCThreadState
    }

    if (gShutdown) {
        ALOGW("Calling IPCThreadState::self() during shutdown is dangerous, expect a crash.\n");
        return nullptr;
    }

    pthread_mutex_lock(&gTLSMutex);
    if (!gHaveTLS) {
        int key_create_value = pthread_key_create(&gTLS, threadDestructor);
        if (key_create_value != 0) {
            pthread_mutex_unlock(&gTLSMutex);
            ALOGW("IPCThreadState::self() unable to create TLS key, expect a crash: %s\n",
                    strerror(key_create_value));
            return nullptr;
        }
        gHaveTLS = true;
    }
    pthread_mutex_unlock(&gTLSMutex);
    goto restart;
}
```

LS是指Thread local storage(线程本地储存空间)，每个线程都拥有自己的TLS，并且是私有空间，线程之间不会共享。通过pthread_getspecific/pthread_setspecific函数可以获取/设置这些空间中的内容。从线程本地存储空间中获得保存在其中的IPCThreadState对象

7.IPCThreadState初始化

```c++
IPCThreadState::IPCThreadState()
    : mProcess(ProcessState::self()),
      mWorkSource(kUnsetWorkSource),
      mPropagateWorkSource(false),
      mStrictModePolicy(0),
      mLastTransactionBinderFlags(0),
      mCallRestriction(mProcess->mCallRestriction)
{
    pthread_setspecific(gTLS, this);
    clearCaller();
    mIn.setDataCapacity(256);
    mOut.setDataCapacity(256);
    mIPCThreadStateBase = IPCThreadStateBase::self();
}

```

每个线程都有一个`IPCThreadState`，每个`IPCThreadState`中都有一个mIn、一个mOut。成员变量mProcess保存了ProcessState变量(每个进程只有一个)。

- mIn 用来接收来自Binder设备的数据，默认大小为256字节；
- mOut用来存储发往Binder设备的数据，默认大小为256字节。

在这里补充说明一下Parcel.cpp其实就是个数据包装类，内部通过malloc开辟内存空间，以及realloc去扩容，内部扩容函数为growData，感兴趣可以具体去看
主要是对数据对齐，按顺序写入开辟的堆内存，所以读取也要按写入顺序来。在这里补充说明一下Parcel.cpp其实就是个数据包装类，内部通过malloc开辟内存空间，以及realloc去扩容，内部扩容函数为growData，感兴趣可以具体去看
主要是对数据对齐，按顺序写入开辟的堆内存，所以读取也要按写入顺序来。

8.IPC::transact

```c++
status_t IPCThreadState::transact(int32_t handle,
                                  uint32_t code, const Parcel& data,
                                  Parcel* reply, uint32_t flags)
{
    status_t err;

    flags |= TF_ACCEPT_FDS;

    IF_LOG_TRANSACTIONS() {
        TextOutput::Bundle _b(alog);
        alog << "BC_TRANSACTION thr " << (void*)pthread_self() << " / hand "
            << handle << " / code " << TypeCode(code) << ": "
            << indent << data << dedent << endl;
    }

    LOG_ONEWAY(">>>> SEND from pid %d uid %d %s", getpid(), getuid(),
        (flags & TF_ONE_WAY) == 0 ? "READ REPLY" : "ONE WAY");
        //传输数据
       //进行通讯数据的封装,注意，这里又多出一个标志位BC_TRANSACTION;所有的BC flag均是用户区发给驱动的请求，驱动处理完成后会发回一个BR flag
    err = writeTransactionData(BC_TRANSACTION, flags, handle, code, data, nullptr);

    if (err != NO_ERROR) {
        if (reply) reply->setError(err);
        return (mLastError = err);
    }
    //同步调用方式
    if ((flags & TF_ONE_WAY) == 0) {
        ...
        if (reply) {
        //调用者要求返回结果，此时想底层发送数据并等待返回值
            err = waitForResponse(reply);
        } else {
        //调用者不需要返回值，但还是要等待远程执行完毕
        //用fakeReply来接收返回的Parcel
            Parcel fakeReply;
            err = waitForResponse(&fakeReply);
        }

        IF_LOG_TRANSACTIONS() {
            TextOutput::Bundle _b(alog);
            alog << "BR_REPLY thr " << (void*)pthread_self() << " / hand "
                << handle << ": ";
            if (reply) alog << indent << *reply << dedent << endl;
            else alog << "(none requested)" << endl;
        }
    } else {//异步调用方式，函数会立即返回
        err = waitForResponse(nullptr, nullptr);
    }

    return err;
}

```

9.IPCThreadState::writeTransactionData

```c++
status_t IPCThreadState::writeTransactionData(int32_t cmd, uint32_t binderFlags,
    int32_t handle, uint32_t code, const Parcel& data, status_t* statusBuffer)
{
    binder_transaction_data tr;

    tr.target.ptr = 0; /* Don't pass uninitialized stack data to a remote process */
    tr.target.handle = handle;//handle=0
    tr.code = code;//code=ADD_SERVICE_TRANSACTION
    tr.flags = binderFlags;//binderFlags=0
    tr.cookie = 0;
    tr.sender_pid = 0;
    tr.sender_euid = 0;
// data为记录Media服务信息的Parcel对象
    const status_t err = data.errorCheck();
    if (err == NO_ERROR) {
        tr.data_size = data.ipcDataSize();//mDataSize
        tr.data.ptr.buffer = data.ipcData();//mData
        tr.offsets_size = data.ipcObjectsCount()*sizeof(binder_size_t);//mObjectSize
        tr.data.ptr.offsets = data.ipcObjects();
    } else if (statusBuffer) {
        tr.flags |= TF_STATUS_CODE;
        *statusBuffer = err;
        tr.data_size = sizeof(status_t);
        tr.data.ptr.buffer = reinterpret_cast<uintptr_t>(statusBuffer);
        tr.offsets_size = 0;
        tr.data.ptr.offsets = 0;
    } else {
        return (mLastError = err);
    }

    mOut.writeInt32(cmd);//cmd=BC_TRANSACTION
    mOut.write(&tr, sizeof(tr));//写入binder_transaction_data数据

    return NO_ERROR;
}

```

其中handle的值用来标识目的端，注册服务过程的目的端为service manager，此处handle=0所对应的是binder_context_mgr_node对象，正是service manager所对应的binder实体对象。[binder_transaction_data结构体](http://gityuan.com/2015/11/01/binder-driver/#bindertransactiondata)是binder驱动通信的数据结构，该过程最终是把Binder请求码BC_TRANSACTION和binder_transaction_data结构体写入到`mOut`。

transact过程，先写完binder_transaction_data数据，其中Parcel data的重要成员变量：

- mDataSize:保存在data_size，binder_transaction的数据大小；
- mData: 保存在ptr.buffer, binder_transaction的数据的起始地址；
- mObjectsSize:保存在ptr.offsets_size，记录着flat_binder_object结构体的个数；
- mObjects: 保存在offsets, 记录着flat_binder_object结构体在数据偏移量；

10.IPCThreadState::waitForResponse

```c++
status_t IPCThreadState::waitForResponse(Parcel *reply, status_t *acquireResult)
{
    uint32_t cmd;
    int32_t err;
//循环和驱动通信获取回复
    while (1) {
        //talkWithDriver()真正和驱动通信
        if ((err=talkWithDriver()) < NO_ERROR) break;
        err = mIn.errorCheck();
        if (err < NO_ERROR) break;
        if (mIn.dataAvail() == 0) continue;

        cmd = (uint32_t)mIn.readInt32();

        IF_LOG_COMMANDS() {
            alog << "Processing waitForResponse Command: "
                << getReturnString(cmd) << endl;
        }

        switch (cmd) {
        case BR_TRANSACTION_COMPLETE:
            if (!reply && !acquireResult) goto finish;
            break;

        case BR_DEAD_REPLY:
            err = DEAD_OBJECT;
            goto finish;

        case BR_FAILED_REPLY:
            err = FAILED_TRANSACTION;
            goto finish;

        case BR_ACQUIRE_RESULT:
            {
                ALOG_ASSERT(acquireResult != NULL, "Unexpected brACQUIRE_RESULT");
                const int32_t result = mIn.readInt32();
                if (!acquireResult) continue;
                *acquireResult = result ? NO_ERROR : INVALID_OPERATION;
            }
            goto finish;

        case BR_REPLY:
            {
                binder_transaction_data tr;
                err = mIn.read(&tr, sizeof(tr));
                ALOG_ASSERT(err == NO_ERROR, "Not enough command data for brREPLY");
                if (err != NO_ERROR) goto finish;

                if (reply) {
                    if ((tr.flags & TF_STATUS_CODE) == 0) {
                        reply->ipcSetDataReference(
                            reinterpret_cast<const uint8_t*>(tr.data.ptr.buffer),
                            tr.data_size,
                            reinterpret_cast<const binder_size_t*>(tr.data.ptr.offsets),
                            tr.offsets_size/sizeof(binder_size_t),
                            freeBuffer, this);
                    } else {
                        err = *reinterpret_cast<const status_t*>(tr.data.ptr.buffer);
                        freeBuffer(nullptr,
                            reinterpret_cast<const uint8_t*>(tr.data.ptr.buffer),
                            tr.data_size,
                            reinterpret_cast<const binder_size_t*>(tr.data.ptr.offsets),
                            tr.offsets_size/sizeof(binder_size_t), this);
                    }
                } else {
                    freeBuffer(nullptr,
                        reinterpret_cast<const uint8_t*>(tr.data.ptr.buffer),
                        tr.data_size,
                        reinterpret_cast<const binder_size_t*>(tr.data.ptr.offsets),
                        tr.offsets_size/sizeof(binder_size_t), this);
                    continue;
                }
            }
            goto finish;

        default:
            err = executeCommand(cmd);
            if (err != NO_ERROR) goto finish;
            break;
        }
    }

finish:
    if (err != NO_ERROR) {
        if (acquireResult) *acquireResult = err;
        if (reply) reply->setError(err);
        mLastError = err;
    }

    return err;
}
```

11.IPCThreadState::talkWithDriver

```c++
status_t IPCThreadState::talkWithDriver(bool doReceive)
{
   //doReceiver 默认true
    if (mProcess->mDriverFD <= 0) {
        return -EBADF;
    }

    binder_write_read bwr;

    // Is the read buffer empty?
    const bool needRead = mIn.dataPosition() >= mIn.dataSize();

    // We don't want to write anything if we are still reading
    // from data left in the input buffer and the caller
    // has requested to read the next data.
    const size_t outAvail = (!doReceive || needRead) ? mOut.dataSize() : 0;

    bwr.write_size = outAvail;
    bwr.write_buffer = (uintptr_t)mOut.data();

    // This is what we'll read.
    if (doReceive && needRead) {
        //接收数据缓冲区信息的填充，以后收到数据直接填在mIn中
        bwr.read_size = mIn.dataCapacity();
        bwr.read_buffer = (uintptr_t)mIn.data();
    } else {
        bwr.read_size = 0;
        bwr.read_buffer = 0;
    }
 ...

    // Return immediately if there is nothing to do.
    //读缓冲和写缓冲都是空，直接返回
    if ((bwr.write_size == 0) && (bwr.read_size == 0)) return NO_ERROR;

    bwr.write_consumed = 0;
    bwr.read_consumed = 0;
    status_t err;
    do {
        IF_LOG_COMMANDS() {
            alog << "About to read/write, write size = " << mOut.dataSize() << endl;
        }
#if defined(__ANDROID__)
        //通过ioctl不停的读写操作，和Binder driver进行通信
        if (ioctl(mProcess->mDriverFD, BINDER_WRITE_READ, &bwr) >= 0)
            err = NO_ERROR;
        else
            err = -errno;
#else
        err = INVALID_OPERATION;
#endif
        if (mProcess->mDriverFD <= 0) {
            err = -EBADF;
        }
        IF_LOG_COMMANDS() {
            alog << "Finished read/write, write size = " << mOut.dataSize() << endl;
        }
    } while (err == -EINTR);//当被中断，则继续执行

    IF_LOG_COMMANDS() {
        alog << "Our err: " << (void*)(intptr_t)err << ", write consumed: "
            << bwr.write_consumed << " (of " << mOut.dataSize()
                        << "), read consumed: " << bwr.read_consumed << endl;
    }

    if (err >= NO_ERROR) {
         //通讯结束后，binder驱动对数据的处理情况放在了bwr的consumed里
        //如果驱动消耗了write数据
        if (bwr.write_consumed > 0) {
            //判断消耗类多少，把已经消耗掉的从out里去掉，下次循环会接着去发送剩下数据
            if (bwr.write_consumed < mOut.dataSize())
                mOut.remove(0, bwr.write_consumed);
            else {
                //驱动全部处理了发送给他的数据，那么直接将out清空
                mOut.setDataSize(0);
                processPostWriteDerefs();
            }
        }
         //如果驱动帮我们成功read到了需要的数据，将数据存储到in中
        if (bwr.read_consumed > 0) {
            mIn.setDataSize(bwr.read_consumed);
            mIn.setDataPosition(0);
        }
       ...
        return NO_ERROR;
    }

    return err;
}
```

所有数据的提供和要求都放到了binder_write_read bwr,并且添加了一个新的flag为BINDER_WRITE_READ
此时bwr的数据里:cmd为BINDER_WRITE_READ,handle是构造BpBinder时传入的0,code是addService时传入的ADD_SERVICE_TRANSACTION，
bwr的write_buffer里放着cmd(BC_TRANSACTION)+BBinder的service对象