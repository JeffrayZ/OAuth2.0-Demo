/*
 * Copyright 2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.example.client.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class LoopbackIpRedirectFilter extends OncePerRequestFilter {

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		// 检查请求的服务器名称是否为localhost，并且host头字段不为空
		if (request.getServerName().equals("localhost") && request.getHeader("host") != null) {
			// 构建新的URI，将host替换为127.0.0.1
			UriComponents uri = UriComponentsBuilder.fromHttpRequest(new ServletServerHttpRequest(request))
					.host("127.0.0.1").build();
			// 发送重定向响应到构建的URI
			response.sendRedirect(uri.toUriString());
			return;
		}
		// 如果不满足重定向条件，则继续处理链中的下一个过滤器或目标资源
		filterChain.doFilter(request, response);
	}

}
