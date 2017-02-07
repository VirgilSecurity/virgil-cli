stage 'VCS checkout'

node('master'){
	deleteDir()
	checkout scm
	stash includes: '**', name: 'src'
}

stage 'Build'

def slaves = [:]
slaves['build-centos7'] = createCentos('build-centos7')
slaves['darwin'] = createDarwin('build-os-x')

parallel slaves

def createCentos(slaveName) {
	println "Building for Centos7"
	return{
		node(slaveName){
			deleteDir()
			unstash 'src'
			dir("build"){
				sh "cmake -DCMAKE_BUILD_TYPE=Release -DUSE_BOOST_REGEX=ON .."
				sh "make -j4 && cpack"
                def name = readFile('virgil_cli_name.txt')
				archiveArtifacts("${name}*")
			}
		}
	}
}

def createDarwin(slaveName) {
	println "Building for MacOS"
	return{
		node(slaveName){
			deleteDir()
			unstash 'src'
			dir("build"){
				sh "cmake -DCMAKE_BUILD_TYPE=Release .."
				sh "make -j4 && cpack"
                def name = readFile('virgil_cli_name.txt')
				archiveArtifacts("${name}*")
			}
		}
	}
}

def archiveArtifacts(pattern) {
    step([$class: 'ArtifactArchiver', artifacts: pattern, fingerprint: true, onlyIfSuccessful: true])
}
