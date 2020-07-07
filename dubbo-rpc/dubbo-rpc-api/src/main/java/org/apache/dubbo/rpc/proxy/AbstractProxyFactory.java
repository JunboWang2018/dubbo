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
package org.apache.dubbo.rpc.proxy;

import org.apache.dubbo.common.utils.ReflectUtils;
import org.apache.dubbo.rpc.Constants;
import org.apache.dubbo.rpc.Invoker;
import org.apache.dubbo.rpc.ProxyFactory;
import org.apache.dubbo.rpc.RpcException;
import org.apache.dubbo.rpc.service.Destroyable;
import org.apache.dubbo.rpc.service.GenericService;

import com.alibaba.dubbo.rpc.service.EchoService;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.apache.dubbo.common.constants.CommonConstants.COMMA_SPLIT_PATTERN;
import static org.apache.dubbo.rpc.Constants.INTERFACES;

/**
 * AbstractProxyFactory
 */
public abstract class AbstractProxyFactory implements ProxyFactory {
    private static final Class<?>[] INTERNAL_INTERFACES = new Class<?>[]{
            EchoService.class, Destroyable.class
    };

    @Override
    public <T> T getProxy(Invoker<T> invoker) throws RpcException {
        return getProxy(invoker, false);
    }

    @Override
    public <T> T getProxy(Invoker<T> invoker, boolean generic) throws RpcException {
        Set<Class<?>> interfaces = new HashSet<>();

        String config = invoker.getUrl().getParameter(INTERFACES);
        if (config != null && config.length() > 0) {
            String[] types = COMMA_SPLIT_PATTERN.split(config);
            for (String type : types) {
                // TODO can we load successfully for a different classloader?.
                interfaces.add(ReflectUtils.forName(type));
            }
        }

        if (generic) {
            if (!GenericService.class.isAssignableFrom(invoker.getInterface())) {
                interfaces.add(com.alibaba.dubbo.rpc.service.GenericService.class);
            }

            try {
                // find the real interface from url
                String realInterface = invoker.getUrl().getParameter(Constants.INTERFACE);
                interfaces.add(ReflectUtils.forName(realInterface));
            } catch (Throwable e) {
                // ignore
            }
        }
        // 指定代理对象 有哪些哪些接口
        interfaces.add(invoker.getInterface());
        interfaces.addAll(Arrays.asList(INTERNAL_INTERFACES));
        // tony:创建 代理对象,本质就是生成一个代理对象，当调用里面方法的时候，根据调用的信息，生成RpcInvocation对象，然后调用Invoker的invoke方法
        return getProxy(invoker, interfaces.toArray(new Class<?>[0]));
    }
    // tony: JavassistProxyFactory 看官网即可
    public abstract <T> T getProxy(Invoker<T> invoker, Class<?>[] types);

}
