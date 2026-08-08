
plugins {
    id("buildlogic.java-library-conventions")
    id("buildlogic.publish-conventions")
}

description = "Hofmann server implementation"

/*
 * The API docs ship inside the jar, but NOT under META-INF/resources.
 *
 * That directory is not an arbitrary choice of location — the Servlet specification makes it a
 * container-published path, and Spring Boot's default static-resource handling serves
 * `classpath:/META-INF/resources/` with no configuration at all. So packaging the docs there
 * published them from every consumer's application in both integrations, and only the Dropwizard
 * side had a switch. A reviewer demonstrated a Spring consumer whose security chain permits the
 * api-docs path serving all four files with no Content-Security-Policy and no Referrer-Policy;
 * the library had no way to prevent it, because the container was doing the serving.
 *
 * (Do not write a Kotlin-style doc-comment opener inside this block. Kotlin nests block comments,
 * unlike Java, so an inner one silently swallows the rest of the file up to the next close — it
 * ate the dependencies block below and produced "package org.slf4j does not exist".)
 *
 * Under META-INF/hofmann/api-docs nothing auto-publishes them. The Dropwizard bundle points its
 * AssetServlet at this path when `serveApiDocs` is enabled, which makes serving the docs a
 * decision rather than a side effect of depending on this artifact.
 */
tasks.processResources {
    from(rootDir.resolve("docs")) {
        include("*.yaml", "*.html")
        into("META-INF/hofmann/api-docs")
    }
}

dependencies {
    api(project(":hofmann-rfc"))

    compileOnly(libs.jakarta.rs.api)
    compileOnly(libs.jakarta.servlet.api)
    implementation(libs.auth0.jwt)
    implementation(libs.javax.inject)
    implementation(libs.bundles.core)
    implementation(libs.bundles.jackson)

    testImplementation(libs.jakarta.rs.api)
    testImplementation(libs.jakarta.servlet.api)
    testImplementation(libs.bundles.test)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
