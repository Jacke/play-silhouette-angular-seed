package dao

import javax.inject.Inject

import com.mohiva.play.silhouette.api.LoginInfo
import com.mohiva.play.silhouette.api.util.PasswordInfo
import com.mohiva.play.silhouette.persistence.daos.DelegableAuthInfoDAO
import play.api.db.slick.DatabaseConfigProvider
import play.api.libs.json.Json
import scala.concurrent.{ ExecutionContext, Future }
import scala.collection.mutable
import scala.concurrent.Future

import com.mohiva.play.silhouette.api.LoginInfo
import com.mohiva.play.silhouette.impl.providers.OAuth2Info
import scala.concurrent.Future

import com.mohiva.play.silhouette.api._
import com.mohiva.play.silhouette.persistence.daos.DelegableAuthInfoDAO
import com.mohiva.play.silhouette.impl.providers.OAuth2Info

trait OAuth2InfoDAO extends DelegableAuthInfoDAO[OAuth2Info] {
  def add(loginInfo: LoginInfo, authInfo: OAuth2Info): Future[OAuth2Info]
  def remove(loginInfo: com.mohiva.play.silhouette.api.LoginInfo): scala.concurrent.Future[Unit]
  def update(loginInfo: com.mohiva.play.silhouette.api.LoginInfo, authInfo: com.mohiva.play.silhouette.impl.providers.OAuth2Info): scala.concurrent.Future[com.mohiva.play.silhouette.impl.providers.OAuth2Info]
  def find(loginInfo: LoginInfo): Future[Option[OAuth2Info]]
  def schema(): Future[String]
}

class OAuth2InfoDAOImpl @Inject() (
  protected val dbConfigProvider: DatabaseConfigProvider)(
  implicit
  ex: ExecutionContext)
  extends OAuth2InfoDAO
  with DAOSlick {

  import profile.api._
  implicit lazy val format = Json.format[OAuth2Info]

  protected def oauthInfoQuery(loginInfo: LoginInfo) =
    for {
      dbLoginInfo <- loginInfoQuery(loginInfo)
      dbPasswordInfo <- oauthInfos
      if dbPasswordInfo.loginInfoId === dbLoginInfo.id
    } yield dbPasswordInfo

  protected def oauthInfoSubQuery(loginInfo: LoginInfo) =
    oauthInfos.filter(_.loginInfoId in loginInfoQuery(loginInfo).map(_.id))

  protected def addAction(loginInfo: LoginInfo, authInfo: OAuth2Info) =
    loginInfoQuery(loginInfo).result.head.flatMap { dbLoginInfo =>
      oauthInfos +=
        DBOauth2Info(
          authInfo.accessToken,
          authInfo.tokenType,
          authInfo.refreshToken,
          dbLoginInfo.id.get)
    }.transactionally

  protected def updateAction(loginInfo: LoginInfo, authInfo: OAuth2Info) =
    oauthInfoSubQuery(loginInfo)
      .map(dbPasswordInfo =>
        (dbPasswordInfo.accessToken, dbPasswordInfo.tokenType, dbPasswordInfo.refreshToken))
      .update((authInfo.accessToken, authInfo.tokenType, authInfo.refreshToken))

  def save(loginInfo: LoginInfo, authInfo: OAuth2Info): Future[OAuth2Info] =
    db.run(addAction(loginInfo, authInfo)).map(_ => authInfo)

  def find(loginInfo: LoginInfo): Future[Option[OAuth2Info]] = {
    println(s"find: $loginInfo")
    db.run(oauthInfoQuery(loginInfo).result.headOption).map {
      case Some(dbPasswordInfo) =>
        Some(
          OAuth2Info(dbPasswordInfo.accessToken, dbPasswordInfo.tokenType, None, dbPasswordInfo.refreshToken)
        )
      case _ => None
    }
  }

  def add(loginInfo: LoginInfo, authInfo: OAuth2Info): Future[OAuth2Info] =
    db.run(addAction(loginInfo, authInfo)).map(_ => authInfo)

  def remove(loginInfo: LoginInfo): Future[Unit] = ???

  def update(loginInfo: LoginInfo, authInfo: OAuth2Info): Future[OAuth2Info] =
    db.run(updateAction(loginInfo, authInfo)).map(_ => authInfo)

  def schema(): Future[String] =
    Future(oauthInfos.schema.create.statements.map(_.toString).mkString(" ")).map(_.toString)
}