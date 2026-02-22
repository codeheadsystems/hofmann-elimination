plugins {
    id("org.owasp.dependencycheck") version "12.1.1"
}

dependencyCheck {
    // Analyze all subprojects
    scanProjects = subprojects.map { it.path }
    // Fail the build if any CVE has a CVSS score >= 7 (high severity)
    failBuildOnCVSS = 7.0f
    // Suppress false positives via this file (create as needed)
    suppressionFile = "config/owasp-suppressions.xml"
}
