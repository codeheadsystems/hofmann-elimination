
plugins {
    id("buildlogic.java-library-conventions")
    id("buildlogic.publish-conventions")
}

description = "Hofmann server implementation"

tasks.processResources {
    from(rootDir.resolve("docs")) {
        include("*.yaml", "*.html")
        into("META-INF/resources/api-docs")
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
