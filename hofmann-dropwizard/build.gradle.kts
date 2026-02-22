
plugins {
    id("buildlogic.java-library-conventions")
}

description = "Hofmann dropwizard bundle for easy integration of Hofmann server into dropwizard applications"

dependencies {
    api(project(":hofmann-server"))

    api(libs.dropwizard.auth)
    api(libs.dropwizard.core)

    testImplementation(project(":hofmann-client"))
    testImplementation(libs.dropwizard.testing)
    testImplementation(libs.bundles.test)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
