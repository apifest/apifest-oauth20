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

import com.apifest.oauth20.api.LifecycleHandler;
import com.apifest.oauth20.api.PostIssueToken;
import com.apifest.oauth20.api.PostRevokeToken;
import com.apifest.oauth20.api.PreIssueToken;
import com.apifest.oauth20.api.PreRevokeToken;

/**
 * Loads lifecycle event handlers on OAuth server startup.
 *
 * @author Rossitsa Borissova
 */
public class LifecycleEventHandlers {

    private static Logger log = LoggerFactory.getLogger(LifecycleEventHandlers.class);

    private static List<Class<LifecycleHandler>> preIssueTokenHandlers = new ArrayList<Class<LifecycleHandler>>();
    private static List<Class<LifecycleHandler>> postIssueTokenHandlers = new ArrayList<Class<LifecycleHandler>>();
    private static List<Class<LifecycleHandler>> preRevokeTokenHandlers = new ArrayList<Class<LifecycleHandler>>();
    private static List<Class<LifecycleHandler>> postRevokeTokenHandlers = new ArrayList<Class<LifecycleHandler>>();

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
                        if (clazz.isAnnotationPresent(PreIssueToken.class)
                                && LifecycleHandler.class.isAssignableFrom(clazz)) {
                            preIssueTokenHandlers.add((Class<LifecycleHandler>) clazz);
                            log.debug("preIssueTokenHandler added {}", className);
                        }
                        if (clazz.isAnnotationPresent(PostIssueToken.class)
                                && LifecycleHandler.class.isAssignableFrom(clazz)) {
                            postIssueTokenHandlers.add((Class<LifecycleHandler>) clazz);
                            log.debug("postIssueTokenHandler added {}", className);
                        }
                        if (clazz.isAnnotationPresent(PreRevokeToken.class)
                                && LifecycleHandler.class.isAssignableFrom(clazz)) {
                            preRevokeTokenHandlers.add((Class<LifecycleHandler>) clazz);
                            log.debug("preRevokeTokenHandler added {}", className);
                        }
                        if (clazz.isAnnotationPresent(PostRevokeToken.class)
                                && LifecycleHandler.class.isAssignableFrom(clazz)) {
                            postRevokeTokenHandlers.add((Class<LifecycleHandler>) clazz);
                            log.debug("postRevokeTokenHandler added {}", className);
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

    public static List<Class<LifecycleHandler>> getPreIssueTokenHandlers() {
        return preIssueTokenHandlers;
    }

    public static List<Class<LifecycleHandler>> getPostIssueTokenHandlers() {
        return postIssueTokenHandlers;
    }

    public static List<Class<LifecycleHandler>> getPreRevokeTokenHandlers() {
        return preRevokeTokenHandlers;
    }

    public static List<Class<LifecycleHandler>> getPostRevokeTokenHandlers() {
        return postRevokeTokenHandlers;
    }
}
