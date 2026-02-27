
plugins {
    id("buildlogic.java-application-conventions")
}

application {
    mainClass.set("com.codeheadsystems.hofmann.testserver.HofmannTestServerApplication")
}

description = "Runnable test server for local developer testing of OPAQUE and OPRF clients"

dependencies {
    implementation(project(":hofmann-dropwizard"))
    implementation(project(":hofmann-client"))

    testImplementation(libs.bundles.test)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

// ── CLI tasks ─────────────────────────────────────────────────────────────────
// Run with: ./gradlew :hofmann-testserver:runOprfCli  --args="<input> [--server url]" -q
//           ./gradlew :hofmann-testserver:runOpaqueCli --args="<cmd> <id> <pwd> [opts]" -q

tasks.register<JavaExec>("runOprfCli") {
    group = "cli"
    description = "Evaluate an input through the testserver OPRF endpoint. " +
            "Usage: --args='<input> [--server <url>]'"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("com.codeheadsystems.hofmann.testserver.cli.OprfCli")
}

tasks.register<JavaExec>("runOpaqueCli") {
    group = "cli"
    description = "Run OPAQUE register / login / whoami against the testserver. " +
            "Usage: --args='register|login|whoami <credentialId> <password> [--server <url>] [--context <ctx>] [--memory <kib>] [--iterations <n>] [--parallelism <n>]'"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("com.codeheadsystems.hofmann.testserver.cli.OpaqueCli")
}
