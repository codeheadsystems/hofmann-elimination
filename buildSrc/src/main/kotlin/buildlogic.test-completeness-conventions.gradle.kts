/*
 * Fails the build when a module's test task produced fewer result files than it has concrete test
 * classes.
 *
 * Gradle's test executor intermittently aborts on its own result bookkeeping — `EOFException`, or
 * `NoSuchFileException` on `in-progress-results-generic.bin` — after running only some classes.
 * The tests themselves pass on a retry. What makes that worth guarding rather than shrugging at is
 * the failure mode: a task that dies before running writes the same thing to disk as a task that
 * had no tests, so the result artifacts cannot distinguish "the suite passed" from "the suite
 * never ran". That ambiguity has already produced two false diagnoses in this repository — a
 * breaking change reported that had in fact been reverted, and a code change blamed for a build
 * failure it had not caused.
 *
 * This does not fix the race. It makes a partial run impossible to mistake for a complete one,
 * which is the part that costs people time.
 */
plugins {
    java
}

val verifyTestsRan = tasks.register("verifyTestsRan") {
    description = "Fails if the test task reported fewer classes than the module actually has."
    group = "verification"

    val testSources = fileTree("src/test/java") { include("**/*Test.java") }
    val resultsDir = layout.buildDirectory.dir("test-results/test")

    // Deliberately not declared as task inputs/outputs. This must run every time — a check that
    // can be skipped as up-to-date cannot tell you the suite failed to run this time, which is
    // the only thing it is for. It reads the results directory at execution time rather than
    // declaring it, because a module with no tests has no such directory.
    outputs.upToDateWhen { false }

    // Resolved at configuration time so the action holds no Project reference — required with the
    // configuration cache enabled.
    val moduleName = project.name
    val concreteTestClasses = testSources.files
        .filterNot { it.readText().contains("abstract class ") }
        .map { it.nameWithoutExtension }
        .toSortedSet()
    val resultsDirFile = resultsDir.get().asFile

    doLast {
        if (concreteTestClasses.isEmpty()) return@doLast

        val reported = (resultsDirFile.listFiles { f -> f.name.endsWith(".xml") } ?: emptyArray())
            .map { it.name }
        // Nested classes produce extra files, and long names are truncated with a hash, so match
        // by containment rather than expecting an exact one-to-one mapping.
        val missing = concreteTestClasses.filter { cls -> reported.none { it.contains(cls) } }

        if (missing.isNotEmpty()) {
            throw GradleException(
                "$moduleName: ${missing.size} test class(es) produced no results, so the suite " +
                    "did not run to completion even though the task did not fail:\n" +
                    missing.joinToString("\n") { "  - $it" } +
                    "\n\nThis is usually Gradle's intermittent test-results bookkeeping abort. " +
                    "Re-run with `clean build`; if it persists, something is genuinely wrong. " +
                    "The check exists because a partial run is otherwise indistinguishable from " +
                    "a complete one."
            )
        }
    }
}

tasks.named("check") { dependsOn(verifyTestsRan) }
verifyTestsRan.configure { mustRunAfter(tasks.named("test")) }
