/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.dubbo.remoting;

import org.apache.dubbo.common.URL;
import org.apache.dubbo.common.Version;
import org.apache.dubbo.common.extension.ExtensionLoader;
import org.apache.dubbo.remoting.transport.ChannelHandlerAdapter;
import org.apache.dubbo.remoting.transport.ChannelHandlerDispatcher;

/**
 * Transporter facade. (API, Static, ThreadSafe)
 */
public class Transporters {

    static {
        // check duplicate jar package
        Version.checkDuplicate(Transporters.class);
        Version.checkDuplicate(RemotingException.class);
    }

    private Transporters() {
    }

    public static RemotingServer bind(String url, ChannelHandler... handler) throws RemotingException {
        return bind(URL.valueOf(url), handler);
    }
    // 到了这个方法的URL示例：dubbo://192.168.97.1:20880/com.study.dubbo.sms.api.SmsService?anyhost=true&application=sms-service&bind.ip=192.168.97.1&bind.port=20880&channel.readonly.sent=true&codec=dubbo&deprecated=false&dubbo=2.0.2&dynamic=true&generic=false&heartbeat=60000&interface=com.study.dubbo.sms.api.SmsService&methods=send&pid=17680&qos.enable=false&release=2.7.7&side=provider&timestamp=1594110250265
    public static RemotingServer bind(URL url, ChannelHandler... handlers) throws RemotingException {
        if (url == null) {
            throw new IllegalArgumentException("url == null");
        }
        if (handlers == null || handlers.length == 0) {
            throw new IllegalArgumentException("handlers == null");
        }
        ChannelHandler handler;
        if (handlers.length == 1) {
            handler = handlers[0];// tony: 这里的handler 是protocol里面传进来的
        } else {
            handler = new ChannelHandlerDispatcher(handlers);// tony:如果有多个，就要做个分发器【其实就是循环调用多个handler】
        }
        return getTransporter().bind(url, handler);// tony:这里往后看就是看基于netty4的实现NettyTransporter的套路了
    }

    public static Client connect(String url, ChannelHandler... handler) throws RemotingException {
        return connect(URL.valueOf(url), handler);
    }

    public static Client connect(URL url, ChannelHandler... handlers) throws RemotingException {
        if (url == null) {
            throw new IllegalArgumentException("url == null");
        }
        ChannelHandler handler;
        if (handlers == null || handlers.length == 0) {
            handler = new ChannelHandlerAdapter();
        } else if (handlers.length == 1) {
            handler = handlers[0];
        } else {
            handler = new ChannelHandlerDispatcher(handlers);// tony:如果有多个，就要做个分发器【其实就是循环调用多个handler】
        }
        return getTransporter().connect(url, handler);// tony:这里往后看就是看基于netty4的实现NettyTransporter的套路了
    }

    public static Transporter getTransporter() {//TONY： 这个Transporter是一个自适应Transporter实例。不过你不用管它，他会自动调用了
        return ExtensionLoader.getExtensionLoader(Transporter.class).getAdaptiveExtension();
    }

}