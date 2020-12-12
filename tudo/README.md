## Building the source

```shell
make td
make tdtest

ANDROID_NDK_HOME=~/Android/Sdk/ndk/21.3.6528147/
ANDROID_HOME=~/Android/Sdk

make android

cp build/bin/{mobile.aar,mobile-sources.jar} <dest>
```

## API

tudo/mobile/app
tudo/proxy/node-api
