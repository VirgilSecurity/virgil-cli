stage 'VCS checkout'

node('master'){
	deleteDir()
  git branch: 'v2.0.0', url: 'https://github.com/VirgilSecurity/virgil-cli.git'
	stash includes: '**', name: 'src'
}


stage 'Build'

def slaves = [:]
slaves['build-centos7'] = createCentos('build-centos7')

parallel slaves

def createCentos(slaveName){
	println "Building for centos7"
	return{
		node(slaveName){
			deleteDir()
			unstash 'src'
			cleanDirectoryLinux("build")
			dir("build"){
				sh "cmake .."
				sh "make"
				cleanDirectoryLinux("install")
				sh "make install DESTDIR=./install"
				dir("install"){
						sh "tar czvf ../virgil-cli.tgz ."
				}
				archiveArtifacts("virgil-cli.tgz")
			}
		}
	}
}

def createWindows(slaveName){
	println "Plug for windows build. It not defined yet"
}

def cleanDirectoryLinux(dirPath) {
	println "Clean directory: ${dirPath}"

	def dirCheck = fileExists dirPath

	switch(dirCheck){
		case true:
			println "Delete directory: ${dirPath}"
			dir(dirPath){
			    deleteDir()
			}
			cleanDirectoryLinux(dirPath)
			break

		case false:
			println "Create directory: ${dirPath}"
			switch(identityOsType()){
				case "nix":
			    sh "mkdir -p ${dirPath}"
					break
				case "win":
			    bat "mkdir ${dirPath}"
					break

				default:
					println "Unknown Slave OS Type"
			}
			break

		default:
			println "[ERROR]: Something goes wrong in cleanDirectoryLinuxLinux function"
	}
}

def identityOsType(){
	println "Detecting slave OS type"
	def osType
	try{
		println "Try by native plugin function:"
		if(isUnix()){
			osType = "nix"
		} else {
			osType = "win"
		}
	} catch(err) {
		println "Sad :( you use very old pipeline plugin version)"
		println "Try by custom function:"
		try {
        sh "uname -a"
        osType = "nix"
    } catch(err1) {
        osType = "win"
    }
	}
	return osType
}

def archiveArtifacts(pattern) {
    step([$class: 'ArtifactArchiver', artifacts: pattern, fingerprint: true, onlyIfSuccessful: true])
}
