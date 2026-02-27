
plugins {
    id("buildlogic.java-application-conventions")
}

application {
    mainClass.set("com.codeheadsystems.hofmann.testserver.HofmannTestServerApplication")
}

description = "Runnable test server for local developer testing of OPAQUE and OPRF clients"

dependencies {
    implementation(project(":hofmann-dropwizard"))

    testImplementation(libs.bundles.test)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
