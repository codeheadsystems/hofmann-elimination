import org.gradle.api.tasks.PathSensitivity


plugins {
    id("buildlogic.java-library-conventions")
    id("buildlogic.publish-conventions")
    // Test-only construction helpers live in src/testFixtures rather than in the main source set.
    // OpaqueConfig.forTesting() builds a config with the identity KSF — no password stretching at
    // all — and it was public on the production API with nothing but a javadoc line between it
    // and a caller who wanted a quick config. Test fixtures are published as a separate
    // classifier and are not on any consumer's compile classpath by default.
    `java-test-fixtures`
}

description = "Hofmann's RFC implementation for OPRF and OPAQUE"

// gradlew is generated: `./gradlew wrapper` rewrites it from the distribution template and would
// silently drop the build lock added to it, whose absence has no symptom until two builds happen
// to overlap. One task, two conditions, wired into check.
//
// A task rather than a JUnit test, after the first attempt was both: a test class in a
// cryptography module reading a shell script is the wrong home, and making gradlew an input to
// that module's `test` task meant every gradlew edit re-ran ~1400 crypto tests. This re-runs only
// itself.
val verifyBuildLock by tasks.registering {
    val gradlewScript = rootProject.layout.projectDirectory.file("gradlew").asFile
    val stamp = layout.buildDirectory.file("verify-build-lock.stamp")
    inputs.file(gradlewScript).withPropertyName("gradlew").withPathSensitivity(PathSensitivity.NONE)
    outputs.file(stamp)
    doLast {
        val script = gradlewScript.readText()
        val lock = script.indexOf("flock -n 9")
        val exec = script.lastIndexOf("exec \"\$JAVACMD\"")
        check(lock in 0 until exec) {
            "gradlew has lost its build lock — concurrent builds in one directory corrupt each " +
                "other's build/ outputs, and the failure looks like a flaky test. A wrapper " +
                "upgrade drops it. Restore the flock block above `exec \"\$JAVACMD\"` rather " +
                "than deleting this check; see the comment in gradlew for what it does and why."
        }
        stamp.get().asFile.writeText("ok")
    }
}

tasks.named("check") { dependsOn(verifyBuildLock) }

dependencies {
    implementation(libs.javax.inject)
    implementation(libs.bundles.core)
    implementation(libs.bundles.jackson)

    testImplementation(libs.bundles.test)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")

    testFixturesImplementation(libs.bundles.core)
}