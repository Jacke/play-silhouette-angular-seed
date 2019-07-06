// Comment to get more information during initialization
logLevel := Level.Warn

resolvers += Resolver.bintrayRepo("givers", "maven")


addSbtPlugin("com.typesafe.play" % "sbt-plugin" % "2.7.3")

addSbtPlugin("org.scalariform" % "sbt-scalariform" % "1.8.2")

addSbtPlugin("givers.webpack" % "sbt-webpack" % "0.7.0")
