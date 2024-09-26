import jenkins.model.*
import org.jenkinsci.plugins.cas.*
import org.jenkinsci.plugins.cas.protocols.*

def jlc = JenkinsLocationConfiguration.get()
jlc.setUrl("http://localhost:8080/")
jlc.save()

def casProtocol = new Cas30Protocol("groups,roles", "cn", "mail", "", false, false, "", false)
def casSecurityRealm = new CasSecurityRealm("https://localhost:8443/cas/", casProtocol, false, true, true, true)

def instance = Jenkins.getInstance()
instance.setSecurityRealm(casSecurityRealm)
instance.save()
