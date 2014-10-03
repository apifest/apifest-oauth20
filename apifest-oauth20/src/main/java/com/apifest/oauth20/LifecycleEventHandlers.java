/*
 * Copyright 2014, ApiFest project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.apifest.oauth20;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.apifest.oauth20.api.ExceptionEventHandler;
import com.apifest.oauth20.api.LifecycleHandler;
import com.apifest.oauth20.api.OnException;
import com.apifest.oauth20.api.OnResponse;
import com.apifest.oauth20.api.OnRequest;

/**
 * Loads lifecycle event handlers on OAuth server startup.
 *
 * @author Rossitsa Borissova
 */
public class LifecycleEventHandlers {

    private static Logger log = LoggerFactory.getLogger(LifecycleEventHandlers.class);

    private static List<Class<LifecycleHandler>> requestEventHandlers = new ArrayList<Class<LifecycleHandler>>();
    private static List<Class<LifecycleHandler>> responseEventHandlers = new ArrayList<Class<LifecycleHandler>>();
    private static List<Class<ExceptionEventHandler>> exceptionHandlers = new ArrayList<Class<ExceptionEventHandler>>();

    @SuppressWarnings("unchecked")
    public static void loadLifecycleHandlers(URLClassLoader classLoader, String customJar) {
        try {
            if (classLoader != null) {
                JarFile jarFile = new JarFile(customJar);
                Enumeration<JarEntry> entries = jarFile.entries();
                while (entries.hasMoreElements()) {
                    JarEntry entry = entries.nextElement();
                    if (entry.isDirectory() || !entry.getName().endsWith(".class")) {
                        continue;
                    }
                    // remove .class
                    String className = entry.getName().substring(0, entry.getName().length() - 6);
                    className = className.replace('/', '.');
                    try {
                        // REVISIT: check for better solution
                        if (className.startsWith("org.jboss.netty") || className.startsWith("org.apache.log4j")
                                || className.startsWith("org.apache.commons")) {
                            continue;
                        }
                        Class<?> clazz = classLoader.loadClass(className);
                        if (clazz.isAnnotationPresent(OnRequest.class)
                                && LifecycleHandler.class.isAssignableFrom(clazz)) {
                            requestEventHandlers.add((Class<LifecycleHandler>) clazz);
                            log.debug("preIssueTokenHandler added {}", className);
                        }
                        if (clazz.isAnnotationPresent(OnResponse.class)
                                && LifecycleHandler.class.isAssignableFrom(clazz)) {
                            responseEventHandlers.add((Class<LifecycleHandler>) clazz);
                            log.debug("postIssueTokenHandler added {}", className);
                        }
                        if (clazz.isAnnotationPresent(OnException.class)
                                && ExceptionEventHandler.class.isAssignableFrom(clazz)) {
                            exceptionHandlers.add((Class<ExceptionEventHandler>) clazz);
                            log.debug("exceptionHandlers added {}", className);
                        }
                    } catch (ClassNotFoundException e1) {
                        // continue
                    }
                }
            }
        } catch (MalformedURLException e) {
            log.error("cannot load lifecycle handlers", e);
        } catch (IOException e) {
            log.error("cannot load lifecycle handlers", e);
        } catch (IllegalArgumentException e) {
            log.error(e.getMessage());
        }
    }

    public static List<Class<LifecycleHandler>> getRequestEventHandlers() {
        return requestEventHandlers;
    }

    public static List<Class<LifecycleHandler>> getResponseEventHandlers() {
        return responseEventHandlers;
    }

    public static List<Class<ExceptionEventHandler>> getExceptionHandlers() {
        return exceptionHandlers;
    }
}
