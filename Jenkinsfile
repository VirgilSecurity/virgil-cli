stage 'VCS checkout'

node('master'){
	deleteDir()
	checkout scm
	stash includes: '**', name: 'src'
}

stage 'Build'

def slaves = [:]
slaves['build-centos7'] = createCentos('build-centos7')

parallel slaves

def createCentos(slaveName){
	println "Building for Centos7"
	return{
		node(slaveName){
			deleteDir()
			unstash 'src'
			dir("build"){
				sh "cmake -DUSE_BOOST_REGEX=ON -DCMAKE_INSTALL_PREFIX=./install .."
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
