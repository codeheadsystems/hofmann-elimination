
import java.net.URLClassLoader
import java.util.jar.JarFile

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

dependencies {
    implementation(libs.javax.inject)
    implementation(libs.bundles.core)
    implementation(libs.bundles.jackson)

    testImplementation(libs.bundles.test)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")

    testFixturesImplementation(libs.bundles.core)
}

// ─── Sealing com.codeheadsystems.rfc.opaque ───────────────────────────────────
//
// The OPAQUE deterministic entry points — fixed blind, fixed masking nonce, fixed server AKE
// seed — are package-private, and `Client`'s section comment explains what each one costs when a
// production caller reaches it. Package-private is not on its own a boundary: a class declared in
// `com.codeheadsystems.rfc.opaque` in some *other* jar compiles against those methods and calls
// them, because the compiler asks only whether the package names match.
//
// Sealing is what makes the package name insufficient. A sealed package must be loaded entirely
// from one code source, so `URLClassLoader` refuses the intruder with a sealing violation at
// class-definition time rather than at first call.
//
// Only this package is sealed, not the whole jar. Sealing is enforced per code source, so a
// blanket seal would also be a standing constraint on `...rfc.oprf` and `...rfc.ellipticcurve`,
// neither of which is defending anything, in exchange for a class of build failure — shading,
// relocation, a jar merged by a fat-jar plugin — that is hard to read backwards from the
// exception.
//
// Sealing rather than a `module-info.java`, which was the other option on the table: this
// library is consumed from the class path, and there a `module-info` is inert. It only takes
// effect on the module path, which would leave the ordinary consumer exactly where they started.
// Sealing works in both places.
tasks.jar {
    manifest {
        attributes(mapOf("Sealed" to "true"), "com/codeheadsystems/rfc/opaque/")
    }
}

// The manifest above is the only thing standing between a consumer and the deterministic entry
// points, and nothing else in the build would notice if it were dropped — the jar keeps building,
// every test keeps passing. So assert it on the built artifact.
//
// Asserted by *loading*, not by reading the manifest string. A string check would pass against a
// manifest that is present but ineffective — a section name written without its trailing slash, a
// future JDK that stops enforcing sealing for some packaging, a fat-jar step that rewrites the
// entry. What has to hold is the behaviour: a class in this package arriving from a second code
// source must be refused.
//
// The intruder is `build/classes/java/test`, which is a genuine second code source for this
// package — the OPAQUE tests are white-box and live in it — and which the build has already
// produced. That avoids compiling a throwaway class here, and it is the same shape as the attack:
// this package's name, someone else's code source.
val verifyOpaquePackageSealed = tasks.register("verifyOpaquePackageSealed") {
    val jarFile = tasks.jar.flatMap { it.archiveFile }
    val intruderDir = sourceSets["test"].output.classesDirs
    inputs.file(jarFile)
    inputs.files(intruderDir)
    dependsOn(tasks.named("testClasses"))
    doLast {
        val sealedPackage = "com/codeheadsystems/rfc/opaque/"
        val jar = jarFile.get().asFile

        JarFile(jar).use { opened ->
            val sealed: String? = opened.manifest?.getAttributes(sealedPackage)?.getValue("Sealed")
            if (!"true".equals(sealed, ignoreCase = true)) {
                throw GradleException(
                    "$sealedPackage is not sealed in ${jar.name}. Sealing is what stops a class "
                        + "declared in that package in another jar from calling the package-private "
                        + "OPAQUE deterministic entry points. Restore the manifest section in "
                        + "hofmann-rfc/build.gradle.kts."
                )
            }
        }

        // Null parent, so nothing resolves through the build's own class path and the jar is
        // genuinely the code source under test. Neither class is initialised; defining them is
        // the whole experiment.
        val urls = (listOf(jar) + intruderDir.files).map { it.toURI().toURL() }.toTypedArray()
        URLClassLoader(urls, null).use { loader ->
            // Defines the package from the sealed jar.
            Class.forName("com.codeheadsystems.rfc.opaque.Client", false, loader)
            val refused = try {
                Class.forName("com.codeheadsystems.rfc.opaque.PackageBoundaryTest", false, loader)
                false
            } catch (e: SecurityException) {
                logger.info("sealing refused the second code source as intended: ${e.message}")
                true
            }
            if (!refused) {
                throw GradleException(
                    "${jar.name} declares $sealedPackage sealed, but a class in that package "
                        + "loaded anyway from a second code source. The manifest is present and "
                        + "not being enforced, so the package-private OPAQUE deterministic entry "
                        + "points are reachable from any jar that declares this package."
                )
            }
        }
    }
}

tasks.check {
    dependsOn(verifyOpaquePackageSealed)
}

// Sealing has one consequence inside this build, and it is not optional to handle.
//
// This module's OPAQUE tests are white-box: they live in `com.codeheadsystems.rfc.opaque` because
// that is the only way to exercise the package-private entry points, so `build/classes/java/test`
// is a second code source for a sealed package. Ordinarily that would not arise — Gradle puts
// `build/classes/java/main` on the test runtime classpath, and a directory carries no manifest —
// but `java-test-fixtures` adds a dependency on this project's own *published* component, and the
// jar it resolves to displaces the classes directory entirely. The result is a sealing violation
// raised while loading `Client`, before a single test body runs.
//
// So put the classes directory back and drop the jar. Same bytecode, produced by the same
// compilation; the only thing left behind is the manifest, which `verifyOpaquePackageSealed`
// checks on the artifact itself. Nothing else on the classpath declares a class in a sealed
// package, so this is the one substitution needed.
// Subtracted rather than filtered with a lambda: a lambda in a Kotlin build script captures the
// script object, which the configuration cache refuses to serialise.
val mainClassesJar = files(tasks.jar.map { it.archiveFile })
tasks.test {
    classpath = sourceSets["main"].output + (sourceSets["test"].runtimeClasspath - mainClassesJar)
}
